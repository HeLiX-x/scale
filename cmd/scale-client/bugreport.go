package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func cmdBugreport(_ []string) error {
	if err := ensureScaleDir(); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Scale VPN Bugreport\n")
	fmt.Fprintf(&b, "Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Version: %s commit=%s go=%s %s/%s\n\n", Version, GitCommit, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	fmt.Fprintf(&b, "== OS / Kernel ==\n")
	b.WriteString(runCapture("uname", "-a"))
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		b.WriteString(sanitize(string(data)))
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "== Interface State ==\n")
	b.WriteString(runCapture("ip", "link", "show"))
	b.WriteString(runCapture("ip", "addr", "show", "dev", "wg0"))
	b.WriteString(runCapture("ip", "route"))
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "== VPN Runtime ==\n")
	if pid, ok := runningPID(); ok {
		fmt.Fprintf(&b, "process: running pid=%d\n", pid)
	} else {
		fmt.Fprintf(&b, "process: not running\n")
	}
	snap, err := fetchLiveSnapshot()
	if err != nil {
		fmt.Fprintf(&b, "snapshot: unavailable (%v)\n", err)
	} else {
		fmt.Fprintf(&b, "status: %s\n", dash(snap.Status))
		fmt.Fprintf(&b, "interface: %s\n", dash(snap.Interface))
		fmt.Fprintf(&b, "overlay_ip: %s\n", dash(snap.OverlayIP))
		fmt.Fprintf(&b, "public_key: %s\n", shortKey(snap.PublicKey))
		fmt.Fprintf(&b, "control_server: %s ok=%v\n", redactURL(snap.ControlServer), snap.ControlOK)
		fmt.Fprintf(&b, "relay_server: %s connected=%v using_relay=%v\n", redactURL(snap.RelayServer), snap.RelayConnected, snap.UsingRelay)
		fmt.Fprintf(&b, "nat_type: %s\n", dash(snap.NATType))
		fmt.Fprintf(&b, "peer_count: %d\n", snap.ActivePeers)
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "== Local Config (redacted) ==\n")
	cfg := loadConfig()
	fmt.Fprintf(&b, "control_server: %s\n", redactURL(cfg.ControlServer))
	fmt.Fprintf(&b, "relay_url: %s\n", redactURL(cfg.RelayURL))
	fmt.Fprintf(&b, "token_present: %v\n", readToken() != "")
	if st, err := os.Stat(keyPath()); err == nil {
		fmt.Fprintf(&b, "wg_key_present: true mode=%s\n", st.Mode().Perm())
	} else {
		fmt.Fprintf(&b, "wg_key_present: false\n")
	}
	fmt.Fprintf(&b, "\n")

	fmt.Fprintf(&b, "== Environment (allowlist) ==\n")
	for _, key := range []string{"WG_INTERFACE", "WG_PORT", "WG_CONTROL_SERVER", "RELAY_URL"} {
		val := os.Getenv(key)
		if val == "" {
			fmt.Fprintf(&b, "%s=\n", key)
			continue
		}
		if key == "WG_CONTROL_SERVER" || key == "RELAY_URL" {
			val = redactURL(val)
		}
		fmt.Fprintf(&b, "%s=%s\n", key, val)
	}
	fmt.Fprintf(&b, "\nRedaction: JWT, WireGuard private keys, passwords, and secret env vars excluded.\n")

	report := sanitize(b.String())
	name := fmt.Sprintf("bugreport-%s.txt", time.Now().UTC().Format("20060102-150405"))
	outPath := filepath.Join(scaleDir(), name)
	if err := os.WriteFile(outPath, []byte(report), 0600); err != nil {
		return err
	}
	chownToInvoker(outPath)
	fmt.Print(report)
	fmt.Printf("\nWrote %s\n", outPath)
	return nil
}

func runCapture(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("$ %s %s\n(unavailable: %v)\n", name, strings.Join(args, " "), err)
	}
	return fmt.Sprintf("$ %s %s\n%s\n", name, strings.Join(args, " "), strings.TrimSpace(string(out)))
}

func sanitize(s string) string {
	secrets := []string{
		readToken(),
	}
	if data, err := os.ReadFile(keyPath()); err == nil {
		secrets = append(secrets, strings.TrimSpace(string(data)))
	}
	for _, envKey := range []string{
		"AUTH_TOKEN", "SCALE_PASSWORD", "JWT_SECRET", "DEVICE_AUTH_SECRET",
		"DERP_AUTH_KEY", "DB_PASSWORD", "REDIS_PASSWORD", "DATABASE_URL",
	} {
		if v := os.Getenv(envKey); v != "" {
			secrets = append(secrets, v)
		}
	}
	out := s
	for _, sec := range secrets {
		if len(sec) < 6 {
			continue
		}
		out = strings.ReplaceAll(out, sec, "[REDACTED]")
	}
	out = redactBearer(out)
	return out
}

func redactBearer(s string) string {
	var out strings.Builder
	lower := strings.ToLower(s)
	i := 0
	for {
		idx := strings.Index(lower[i:], "bearer ")
		if idx < 0 {
			out.WriteString(s[i:])
			return out.String()
		}
		idx += i
		out.WriteString(s[i:idx])
		out.WriteString("Bearer [REDACTED]")
		j := idx + len("bearer ")
		for j < len(s) && !isSpace(s[j]) {
			j++
		}
		i = j
	}
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\n' || c == '\t' || c == '\r'
}
