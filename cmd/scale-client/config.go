package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	DefaultControlServer = "http://sankalp-scale.duckdns.org:8080"
	DefaultRelayURL      = "wss://sankalp-scale.duckdns.org:8443/derp?auth=2_m0RLKp5f2stxVr3kpvINlJfH6efP0A"

	tokenFileName  = "token"
	keyFileName    = "wg.key"
	configFileName = "config.json"
	socketFileName = "scale.sock"
	pidFileName    = "scale.pid"
	statusFileName = "status.json"
)

type ClientConfig struct {
	ControlServer string `json:"control_server"`
	RelayURL      string `json:"relay_url"`
	Interface     string `json:"interface,omitempty"`
	Port          int    `json:"port,omitempty"`
}

func invokerHome() string {
	if su := os.Getenv("SUDO_USER"); su != "" && os.Geteuid() == 0 {
		if u, err := user.Lookup(su); err == nil && u.HomeDir != "" {
			return u.HomeDir
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return home
}

func scaleDir() string {
	return filepath.Join(invokerHome(), ".scale")
}

func tokenPath() string  { return filepath.Join(scaleDir(), tokenFileName) }
func keyPath() string    { return filepath.Join(scaleDir(), keyFileName) }
func configPath() string { return filepath.Join(scaleDir(), configFileName) }
func socketPath() string { return filepath.Join(scaleDir(), socketFileName) }
func pidPath() string    { return filepath.Join(scaleDir(), pidFileName) }
func statusPath() string { return filepath.Join(scaleDir(), statusFileName) }

func chownToInvoker(path string) {
	if os.Geteuid() != 0 {
		return
	}
	su := os.Getenv("SUDO_USER")
	if su == "" {
		return
	}
	u, err := user.Lookup(su)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}

func ensureScaleDir() error {
	dir := scaleDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	chownToInvoker(dir)
	return nil
}

func writeSecureFile(path string, data []byte, perm os.FileMode) error {
	if err := ensureScaleDir(); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	chownToInvoker(path)
	return nil
}

func loadConfig() ClientConfig {
	var cfg ClientConfig
	data, err := os.ReadFile(configPath())
	if err == nil {
		_ = json.Unmarshal(data, &cfg)
	}
	if cfg.ControlServer == "" {
		cfg.ControlServer = DefaultControlServer
	}
	if cfg.RelayURL == "" {
		cfg.RelayURL = DefaultRelayURL
	}
	return cfg
}

func saveConfig(cfg ClientConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeSecureFile(configPath(), data, 0600)
}

func readToken() string {
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeToken(token string) error {
	return writeSecureFile(tokenPath(), []byte(token+"\n"), 0600)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func requireRoot(cmd string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s requires root privileges. Try: sudo scale %s", cmd, cmd)
	}
	return nil
}

func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8] + "..."
	}
	return k
}
