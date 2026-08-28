package database

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func requireLoopbackAddr(raw, label string) error {
	host, err := hostFromAddr(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("%s must be 127.0.0.1/localhost, got %q", label, host)
	}
	return nil
}

func hostFromAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("address is empty")
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		if u.Hostname() != "" {
			return u.Hostname(), nil
		}
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host, nil
	}
	for _, field := range strings.Fields(raw) {
		if strings.HasPrefix(field, "host=") {
			return strings.TrimPrefix(field, "host="), nil
		}
	}
	if !strings.ContainsAny(raw, "/ =") {
		return raw, nil
	}
	return "localhost", nil
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
