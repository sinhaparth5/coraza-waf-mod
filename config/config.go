package config

import (
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	ListenAddr string      `yaml:"listen_addr"`
	Apps       []App       `yaml:"apps"`
	WAF        WAFConfig   `yaml:"waf"`
	DB         DBConfig    `yaml:"db"`
	Admin      AdminConfig `yaml:"admin"`
}

type App struct {
	Name    string `yaml:"name"`
	Host    string `yaml:"host"`   // virtual-host matching (e.g. "blog.example.com")
	Prefix  string `yaml:"prefix"` // path-prefix matching (e.g. "/api")
	Backend string `yaml:"backend"`
}

type WAFConfig struct {
	Enabled  bool   `yaml:"enabled"`
	RulesDir string `yaml:"rules_dir"`
}

type DBConfig struct {
	Path string `yaml:"path"`
}

type AdminConfig struct {
	Path     string `yaml:"path"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	applyDefaults(&cfg)
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.DB.Path == "" {
		cfg.DB.Path = "waf.db"
	}
	if cfg.Admin.Path == "" {
		cfg.Admin.Path = "/admin"
	}
}
