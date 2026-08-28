package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func cmdDown(_ []string) error {
	if err := requireRoot("down"); err != nil {
		return err
	}

	pid, running := runningPID()
	if running {
		if _, err := ipcCall("stop"); err != nil {
			proc, findErr := os.FindProcess(pid)
			if findErr == nil {
				_ = proc.Signal(os.Interrupt)
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := runningPID(); !ok {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if _, ok := runningPID(); ok {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
			}
		}
	}

	iface := loadConfig().Interface
	if iface == "" {
		iface = os.Getenv("WG_INTERFACE")
	}
	if iface == "" {
		iface = "wg0"
	}
	_ = exec.Command("ip", "link", "delete", iface).Run()
	removePID()
	_ = os.Remove(socketPath())
	_ = os.Remove(statusPath())

	fmt.Println("Scale VPN disconnected. Network interface wg0 removed.")
	return nil
}
