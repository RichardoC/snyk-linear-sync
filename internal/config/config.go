package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

const (
	defaultSnykRegion           = "SNYK-US-01"
	defaultSourceProvider       = "unknown"
	defaultLinearTodoState      = "Todo"
	defaultLinearBacklogState   = "Backlog"
	defaultLinearDoneState      = "Done"
	defaultLinearCancelledState = "Cancelled"
	defaultManagedLabel         = "snyk-automation"
	defaultCriticalDueDays      = 15
	defaultHighDueDays          = 30
	defaultMediumDueDays        = 45
	defaultLowDueDays           = 90
	defaultWorkerCount          = 16
	defaultSnykConcurrency      = 6
	defaultLinearConcurrency    = 8
	defaultErrorLogFile         = "logs/snyk-linear-sync-errors.log"
	defaultCacheDBFile          = "data/snyk-linear-sync-cache.db"
)

type Config struct {
	DryRun bool

	Log    LogConfig
	Cache  CacheConfig
	Snyk   SnykConfig
	Source SourceConfig
	Linear LinearConfig
	Sync   SyncConfig
}

type LogConfig struct {
	ErrorFile string
}

type CacheConfig struct {
	DBFile      string
	BypassCache bool
}

type SnykConfig struct {
	Region       string
	ClientID     string
	ClientSecret string
	OrgID        string
	Scopes       []string
}

type SourceConfig struct {
	Provider string
}

type LinearConfig struct {
	APIKey string
	TeamID string
	States StateConfig
	Labels LabelConfig
	Due    DueDateConfig
}

type StateConfig struct {
	Todo      string
	Backlog   string
	Done      string
	Cancelled string
}

type LabelConfig struct {
	Managed       string
	Tool          map[string]string
	ToolDefault   string
	Origin        map[string]string
	OriginDefault string
}

type DueDateConfig struct {
	CriticalDays int
	HighDays     int
	MediumDays   int
	LowDays      int
}

type SyncConfig struct {
	Workers           int
	SnykConcurrency   int
	LinearConcurrency int
}

func Load(args []string) (Config, error) {
	fs := flag.NewFlagSet("snyk-linear-sync", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	dryRun := fs.Bool("dry-run", false, "plan changes without mutating Linear")
	bypassCache := fs.Bool("bypass-cache", false, "ignore the SQLite sync cache and fetch/compare everything directly")
	envFile := fs.String("env-file", "", "load configuration from a dotenv-style file before reading the process environment")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if strings.TrimSpace(*envFile) != "" {
		path := strings.TrimSpace(*envFile)
		if err := godotenv.Overload(path); err != nil {
			return Config{}, fmt.Errorf("load env file %q: %w", path, err)
		}
	}

	toolLabels, err := parseLabelMap("LINEAR_TOOL_LABELS", os.Getenv("LINEAR_TOOL_LABELS"))
	if err != nil {
		return Config{}, err
	}
	originLabels, err := parseLabelMap("LINEAR_ORIGIN_LABELS", os.Getenv("LINEAR_ORIGIN_LABELS"))
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		DryRun: *dryRun,
		Log: LogConfig{
			ErrorFile: getEnv("ERROR_LOG_FILE", defaultErrorLogFile),
		},
		Cache: CacheConfig{
			DBFile:      getEnv("CACHE_DB_FILE", defaultCacheDBFile),
			BypassCache: *bypassCache,
		},
		Snyk: SnykConfig{
			Region:       getEnv("SNYK_REGION", defaultSnykRegion),
			ClientID:     os.Getenv("SNYK_CLIENT_ID"),
			ClientSecret: os.Getenv("SNYK_CLIENT_SECRET"),
			OrgID:        os.Getenv("SNYK_ORG_ID"),
			Scopes:       splitCSV(os.Getenv("SNYK_OAUTH_SCOPES")),
		},
		Source: SourceConfig{
			Provider: normalizeSourceProvider(getEnv("SOURCE_PROVIDER", defaultSourceProvider)),
		},
		Linear: LinearConfig{
			APIKey: os.Getenv("LINEAR_API_KEY"),
			TeamID: os.Getenv("LINEAR_TEAM_ID"),
			States: StateConfig{
				Todo:      getEnv("LINEAR_STATE_TODO", defaultLinearTodoState),
				Backlog:   getEnv("LINEAR_STATE_BACKLOG", defaultLinearBacklogState),
				Done:      getEnv("LINEAR_STATE_DONE", defaultLinearDoneState),
				Cancelled: getEnv("LINEAR_STATE_CANCELLED", defaultLinearCancelledState),
			},
			Labels: LabelConfig{
				Managed:       normalizeManagedLabel(getEnv("LINEAR_MANAGED_LABEL", defaultManagedLabel)),
				Tool:          toolLabels,
				ToolDefault:   normalizeManagedLabel(getEnv("LINEAR_TOOL_LABEL_DEFAULT", defaultManagedLabel)),
				Origin:        originLabels,
				OriginDefault: normalizeManagedLabel(getEnv("LINEAR_ORIGIN_LABEL_DEFAULT", "")),
			},
			Due: DueDateConfig{
				CriticalDays: getEnvInt("LINEAR_DUE_DAYS_CRITICAL", defaultCriticalDueDays),
				HighDays:     getEnvInt("LINEAR_DUE_DAYS_HIGH", defaultHighDueDays),
				MediumDays:   getEnvInt("LINEAR_DUE_DAYS_MEDIUM", defaultMediumDueDays),
				LowDays:      getEnvInt("LINEAR_DUE_DAYS_LOW", defaultLowDueDays),
			},
		},
		Sync: SyncConfig{
			Workers:           getEnvInt("SYNC_WORKERS", defaultWorkerCount),
			SnykConcurrency:   getEnvInt("SNYK_HTTP_CONCURRENCY", defaultSnykConcurrency),
			LinearConcurrency: getEnvInt("LINEAR_HTTP_CONCURRENCY", defaultLinearConcurrency),
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error

	if c.Snyk.ClientID == "" {
		errs = append(errs, errors.New("SNYK_CLIENT_ID is required"))
	}
	if c.Snyk.ClientSecret == "" {
		errs = append(errs, errors.New("SNYK_CLIENT_SECRET is required"))
	}
	if c.Snyk.OrgID == "" {
		errs = append(errs, errors.New("SNYK_ORG_ID is required"))
	}
	if c.Linear.APIKey == "" {
		errs = append(errs, errors.New("LINEAR_API_KEY is required"))
	}
	if c.Linear.TeamID == "" {
		errs = append(errs, errors.New("LINEAR_TEAM_ID is required"))
	}
	switch c.Source.Provider {
	case "unknown", "github":
	default:
		errs = append(errs, fmt.Errorf("SOURCE_PROVIDER must be one of unknown, github; got %q", c.Source.Provider))
	}
	if strings.TrimSpace(c.Log.ErrorFile) == "" {
		errs = append(errs, errors.New("ERROR_LOG_FILE must not be empty"))
	}
	if strings.TrimSpace(c.Cache.DBFile) == "" {
		errs = append(errs, errors.New("CACHE_DB_FILE must not be empty"))
	}
	if c.Sync.Workers <= 0 {
		errs = append(errs, fmt.Errorf("SYNC_WORKERS must be > 0, got %d", c.Sync.Workers))
	}
	if c.Sync.SnykConcurrency <= 0 {
		errs = append(errs, fmt.Errorf("SNYK_HTTP_CONCURRENCY must be > 0, got %d", c.Sync.SnykConcurrency))
	}
	if c.Sync.LinearConcurrency <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_HTTP_CONCURRENCY must be > 0, got %d", c.Sync.LinearConcurrency))
	}
	if c.Linear.Due.CriticalDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_CRITICAL must be > 0, got %d", c.Linear.Due.CriticalDays))
	}
	if c.Linear.Due.HighDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_HIGH must be > 0, got %d", c.Linear.Due.HighDays))
	}
	if c.Linear.Due.MediumDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_MEDIUM must be > 0, got %d", c.Linear.Due.MediumDays))
	}
	if c.Linear.Due.LowDays <= 0 {
		errs = append(errs, fmt.Errorf("LINEAR_DUE_DAYS_LOW must be > 0, got %d", c.Linear.Due.LowDays))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

func getEnv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}

	return n
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}

	return out
}

func normalizeSourceProvider(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return defaultSourceProvider
	}
	return value
}

func normalizeManagedLabel(raw string) string {
	value := strings.TrimSpace(raw)
	switch strings.ToLower(value) {
	case "", "off", "false", "disabled", "none":
		return ""
	default:
		return value
	}
}

func parseLabelMap(envName, raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	out := make(map[string]string)
	for part := range strings.SplitSeq(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		issueType, label, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("%s entry %q must use key:label format", envName, part)
		}

		issueType = strings.ToLower(strings.TrimSpace(issueType))
		label = normalizeManagedLabel(label)
		if issueType == "" {
			return nil, fmt.Errorf("%s entry %q is missing the key", envName, part)
		}
		if label == "" {
			return nil, fmt.Errorf("%s entry %q is missing the label name", envName, part)
		}

		out[issueType] = label
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
