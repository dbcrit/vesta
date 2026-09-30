// SPDX-License-Identifier: Apache-2.0

// Package agentconfig holds vesta-agent's configuration: defaults, an
// optional strict YAML file, then command-line flags, in increasing
// precedence.
package agentconfig

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/dbcrit/vesta/api/channel"
	v1alpha1 "github.com/dbcrit/vesta/api/v1alpha1"
	"github.com/dbcrit/vesta/host/internal/transport"
)

// Duration is a time.Duration that decodes from a Go duration string.
type Duration struct{ time.Duration }

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return []byte(`"` + d.String() + `"`), nil }

// Config is the agent configuration.
type Config struct {
	NodeName       string                 `json:"nodeName"`
	NRISocket      string                 `json:"nriSocket"`
	PluginName     string                 `json:"pluginName"`
	PluginIndex    string                 `json:"pluginIndex"`
	Handlers       []string               `json:"handlers"`
	KataRunDirs    []string               `json:"kataRunDirs"`
	CtrlPort       uint32                 `json:"ctrlPort"`
	EvtPort        uint32                 `json:"evtPort"`
	GateTimeout    Duration               `json:"gateTimeout"`
	DefaultFailure v1alpha1.FailurePolicy `json:"defaultFailurePolicy"`
	GlobalMode     string                 `json:"globalMode"`
	PolicyFile     string                 `json:"policyFile"`
	MetricsAddr    string                 `json:"metricsAddr"`
	LogLevel       string                 `json:"logLevel"`
	HeartbeatGrace float64                `json:"heartbeatGrace"`
	EventRate      float64                `json:"eventRatePerSandbox"`
	EventBurst     int                    `json:"eventBurstPerSandbox"`
	EventQueue     int                    `json:"eventQueueSize"`
}

// Default returns the defaults.
func Default() Config {
	return Config{
		NRISocket:      "/var/run/nri/nri.sock",
		PluginName:     "vesta",
		PluginIndex:    "90",
		Handlers:       []string{"kata-qemu-vesta"},
		KataRunDirs:    append([]string(nil), transport.DefaultRunDirs...),
		CtrlPort:       channel.DefaultCtrlPort,
		EvtPort:        channel.DefaultEvtPort,
		GateTimeout:    Duration{1500 * time.Millisecond},
		DefaultFailure: v1alpha1.FailureOpen,
		GlobalMode:     "Normal",
		MetricsAddr:    "127.0.0.1:9464",
		LogLevel:       "info",
		HeartbeatGrace: 2,
		EventRate:      1000,
		EventBurst:     2000,
		EventQueue:     8192,
	}
}

const maxConfigFile = 1 << 20

// Load builds the configuration from args (without the program name). A
// "-config" flag names an optional YAML file applied before other flags.
func Load(args []string, getenv func(string) string) (Config, error) {
	cfg := Default()
	fs := flag.NewFlagSet("vesta-agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfgFile := fs.String("config", "", "optional YAML config file")
	// Parse once to find -config, then apply the file, then parse again so
	// flags win over the file.
	bind(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if *cfgFile != "" {
		fileCfg := Default()
		if err := loadFile(*cfgFile, &fileCfg); err != nil {
			return cfg, err
		}
		fs2 := flag.NewFlagSet("vesta-agent", flag.ContinueOnError)
		fs2.SetOutput(io.Discard)
		fs2.String("config", "", "")
		bind(fs2, &fileCfg)
		if err := fs2.Parse(args); err != nil {
			return cfg, err
		}
		cfg = fileCfg
	}
	if cfg.NodeName == "" && getenv != nil {
		cfg.NodeName = getenv("NODE_NAME")
	}
	return cfg, cfg.Validate()
}

// Usage returns the flag help text.
func Usage() string {
	cfg := Default()
	fs := flag.NewFlagSet("vesta-agent", flag.ContinueOnError)
	var b strings.Builder
	fs.SetOutput(&b)
	fs.String("config", "", "optional YAML config file (flags override it)")
	bind(fs, &cfg)
	fs.PrintDefaults()
	return b.String()
}

type listFlag struct{ p *[]string }

func (l listFlag) String() string {
	if l.p == nil {
		return ""
	}
	return strings.Join(*l.p, ",")
}

func (l listFlag) Set(s string) error {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	*l.p = out
	return nil
}

type durFlag struct{ p *Duration }

func (d durFlag) String() string {
	if d.p == nil {
		return ""
	}
	return d.p.String()
}

func (d durFlag) Set(s string) error {
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parse duration: %w", err)
	}
	d.p.Duration = v
	return nil
}

type u32Flag struct{ p *uint32 }

func (u u32Flag) String() string {
	if u.p == nil {
		return "0"
	}
	return fmt.Sprint(*u.p)
}

func (u u32Flag) Set(s string) error {
	var v uint32
	if _, err := fmt.Sscan(s, &v); err != nil {
		return fmt.Errorf("parse uint32: %w", err)
	}
	*u.p = v
	return nil
}

type failureFlag struct{ p *v1alpha1.FailurePolicy }

func (f failureFlag) String() string {
	if f.p == nil {
		return ""
	}
	return string(*f.p)
}

func (f failureFlag) Set(s string) error { *f.p = v1alpha1.FailurePolicy(s); return nil }

func bind(fs *flag.FlagSet, c *Config) {
	fs.StringVar(&c.NodeName, "node-name", c.NodeName, "node name (default $NODE_NAME)")
	fs.StringVar(&c.NRISocket, "nri-socket", c.NRISocket, "NRI socket path")
	fs.StringVar(&c.PluginName, "plugin-name", c.PluginName, "NRI plugin name")
	fs.StringVar(&c.PluginIndex, "plugin-index", c.PluginIndex, "NRI plugin index (two digits)")
	fs.Var(listFlag{&c.Handlers}, "handlers", "comma-separated runtime handlers vesta acts on")
	fs.Var(listFlag{&c.KataRunDirs}, "kata-run-dirs", "comma-separated Kata sandbox state roots holding shim-monitor.sock")
	fs.Var(u32Flag{&c.CtrlPort}, "ctrl-port", "guest vsock CTRL port")
	fs.Var(u32Flag{&c.EvtPort}, "evt-port", "guest vsock EVT port")
	fs.Var(durFlag{&c.GateTimeout}, "gate-timeout", "bound on each NRI hook wait (must stay below the NRI plugin request timeout)")
	fs.Var(failureFlag{&c.DefaultFailure}, "default-failure-policy", "Open or Closed, for containers no policy selects")
	fs.StringVar(&c.GlobalMode, "global-mode", c.GlobalMode, "kill switch: Normal, AuditOnly or Detached")
	fs.StringVar(&c.PolicyFile, "policy-file", c.PolicyFile, "static VestaPolicy YAML file (empty: monitor only)")
	fs.StringVar(&c.MetricsAddr, "metrics-addr", c.MetricsAddr, "listen address for /metrics, /healthz and /readyz (empty disables)")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "debug, info, warn or error")
	fs.Float64Var(&c.HeartbeatGrace, "heartbeat-grace", c.HeartbeatGrace, "alert when no heartbeat arrives within this multiple of the interval")
	fs.Float64Var(&c.EventRate, "event-rate", c.EventRate, "events per second accepted per sandbox")
	fs.IntVar(&c.EventBurst, "event-burst", c.EventBurst, "event burst accepted per sandbox")
	fs.IntVar(&c.EventQueue, "event-queue", c.EventQueue, "export queue length")
}

func loadFile(p string, c *Config) error {
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigFile+1))
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if len(b) > maxConfigFile {
		return fmt.Errorf("config file %s too large", p)
	}
	if err := yaml.UnmarshalStrict(b, c); err != nil {
		return fmt.Errorf("config file %s: %w", p, err)
	}
	return nil
}

// Validate checks the configuration.
func (c Config) Validate() error {
	var errs []error
	if c.NodeName == "" {
		errs = append(errs, errors.New("node name is required (-node-name or $NODE_NAME)"))
	}
	if len(c.Handlers) == 0 {
		errs = append(errs, errors.New("at least one runtime handler is required"))
	}
	if len(c.KataRunDirs) == 0 {
		errs = append(errs, errors.New("at least one Kata run dir is required"))
	}
	for _, d := range c.KataRunDirs {
		if !strings.HasPrefix(d, "/") {
			errs = append(errs, fmt.Errorf("kata run dir %q must be absolute", d))
		}
	}
	if len(c.PluginIndex) != 2 || c.PluginIndex[0] < '0' || c.PluginIndex[0] > '9' || c.PluginIndex[1] < '0' || c.PluginIndex[1] > '9' {
		errs = append(errs, fmt.Errorf("plugin index %q must be two digits", c.PluginIndex))
	}
	if c.CtrlPort == 0 || c.EvtPort == 0 || c.CtrlPort == c.EvtPort {
		errs = append(errs, errors.New("ctrl and evt ports must be non-zero and distinct"))
	}
	if c.GateTimeout.Duration <= 0 || c.GateTimeout.Duration >= 2*time.Second {
		errs = append(errs, fmt.Errorf("gate timeout %s must be > 0 and below the 2s NRI request timeout", c.GateTimeout))
	}
	switch c.DefaultFailure {
	case v1alpha1.FailureOpen, v1alpha1.FailureClosed:
	default:
		errs = append(errs, fmt.Errorf("default failure policy %q: want Open or Closed", c.DefaultFailure))
	}
	switch c.GlobalMode {
	case "Normal", "AuditOnly", "Detached":
	default:
		errs = append(errs, fmt.Errorf("global mode %q: want Normal, AuditOnly or Detached", c.GlobalMode))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log level %q", c.LogLevel))
	}
	if c.HeartbeatGrace < 1 {
		errs = append(errs, errors.New("heartbeat grace must be >= 1"))
	}
	if c.EventRate <= 0 || c.EventBurst <= 0 || c.EventQueue <= 0 {
		errs = append(errs, errors.New("event rate, burst and queue must be positive"))
	}
	return errors.Join(errs...)
}
