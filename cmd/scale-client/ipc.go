package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ipcRequest struct {
	Cmd string `json:"cmd"`
}

type ipcResponse struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

type PeerSnap struct {
	OverlayIP string    `json:"overlay_ip"`
	PublicKey string    `json:"public_key"`
	Transport string    `json:"transport"`
	LastPong  time.Time `json:"last_pong"`
	Status    string    `json:"status"`
}

type RuntimeSnapshot struct {
	Status         string     `json:"status"`
	Interface      string     `json:"interface"`
	OverlayIP      string     `json:"overlay_ip"`
	PublicKey      string     `json:"public_key"`
	ControlServer  string     `json:"control_server"`
	ControlOK      bool       `json:"control_ok"`
	RelayServer    string     `json:"relay_server"`
	RelayConnected bool       `json:"relay_connected"`
	NATType        string     `json:"nat_type"`
	UsingRelay     bool       `json:"using_relay"`
	ActivePeers    int        `json:"active_peers"`
	Peers          []PeerSnap `json:"peers"`
}

func writePID() error {
	if err := ensureScaleDir(); err != nil {
		return err
	}
	if err := os.WriteFile(pidPath(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0644); err != nil {
		return err
	}
	chownToInvoker(pidPath())
	return nil
}

func removePID() {
	_ = os.Remove(pidPath())
}

func runningPID() (int, bool) {
	data, err := os.ReadFile(pidPath())
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return 0, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return 0, false
	}
	return pid, true
}

func startIPC(stop func()) error {
	path := socketPath()
	_ = os.Remove(path)
	if err := ensureScaleDir(); err != nil {
		return err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0660)
	chownToInvoker(path)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleIPC(conn, stop)
		}
	}()
	go func() {
		<-vpnCtx.Done()
		_ = ln.Close()
		_ = os.Remove(path)
	}()
	return nil
}

func handleIPC(conn net.Conn, stop func()) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var req ipcRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	var resp ipcResponse
	switch strings.ToLower(req.Cmd) {
	case "status":
		snapshotMu.RLock()
		raw, _ := json.Marshal(snapshot)
		snapshotMu.RUnlock()
		resp = ipcResponse{OK: true, Data: raw}
	case "peers":
		snapshotMu.RLock()
		raw, _ := json.Marshal(snapshot.Peers)
		snapshotMu.RUnlock()
		resp = ipcResponse{OK: true, Data: raw}
	case "stop":
		resp = ipcResponse{OK: true}
		_ = json.NewEncoder(conn).Encode(resp)
		go func() {
			time.Sleep(50 * time.Millisecond)
			stop()
		}()
		return
	default:
		resp = ipcResponse{OK: false, Error: "unknown command"}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

func ipcCall(cmd string) (*ipcResponse, error) {
	conn, err := net.DialTimeout("unix", socketPath(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(ipcRequest{Cmd: cmd}); err != nil {
		return nil, err
	}
	var resp ipcResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error == "" {
			return nil, fmt.Errorf("ipc %s failed", cmd)
		}
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return &resp, nil
}

func loadSnapshotFile() (RuntimeSnapshot, error) {
	var snap RuntimeSnapshot
	data, err := os.ReadFile(statusPath())
	if err != nil {
		return snap, err
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		return snap, err
	}
	return snap, nil
}

func writeSnapshotFile(snap RuntimeSnapshot) {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(statusPath(), data, 0644)
	chownToInvoker(statusPath())
}

func fetchLiveSnapshot() (RuntimeSnapshot, error) {
	resp, err := ipcCall("status")
	if err != nil {
		return loadSnapshotFile()
	}
	var snap RuntimeSnapshot
	if err := json.Unmarshal(resp.Data, &snap); err != nil {
		return loadSnapshotFile()
	}
	return snap, nil
}
