package types

type Endpoint struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
	Port int    `json:"port"`
}

type PeerInfo struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	Endpoints []Endpoint `json:"endpoints"`
}

type EndpointResponse struct {
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	NATType string `json:"nat_type"` // e.g., "unknown", "easy", "likely_symmetric"
}

type PollResponse struct {
	StunToken string     `json:"stun_token"`
	Peers     []PeerInfo `json:"peers"`
}
