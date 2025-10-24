package types

import (
	"fmt"
	"net"
	"strconv"
)

type Endpoint struct {
	IP       string `json:"ip"`       // Can be IPv4 or IPv6
	Port     int    `json:"port"`     // Port number
	Protocol string `json:"protocol"` // "udp" or "tcp"
	Type     string `json:"type"`     // "host", "srflx" (server reflexive), "relay" (future)
}

// Helper to parse "ip:port" string into a basic Endpoint struct
// We'll set Protocol and Type separately where this is used.
func ParseEndpointAddress(endpointStr string) (ip string, port int, err error) {
	host, portStr, err := net.SplitHostPort(endpointStr)
	if err != nil {
		err = fmt.Errorf("invalid endpoint format '%s': %w", endpointStr, err)
		return
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		err = fmt.Errorf("invalid port '%s': %w", portStr, err)
		return
	}
	ip = host
	return
}

type PeerInfo struct {
	ID        string     `json:"id"` // Still AssignedIP
	PublicKey string     `json:"public_key"`
	Endpoints []Endpoint `json:"endpoints,omitempty"` // Slice to hold all candidates
}

type EndpointResponse struct {
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Port    string `json:"port"`
	NATType string `json:"nat_type"` // e.g., "unknown", "easy", "likely_symmetric"
}

type PollResponse struct {
	StunToken string     `json:"stun_token"`
	Peers     []PeerInfo `json:"peers"`
}
