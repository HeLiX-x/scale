package ipmanager

import (
	"net"
	"sync"
)

type IPNet struct {
	IP   net.IP
	Mask net.IPMask
}

type IPAllocator struct {
	baseIPNet      *net.IPNet
	lastIPNet      *net.IPNet
	freedBlocks    map[uint8][]string
	reservedIPNets []*net.IPNet
	mutex          sync.Mutex
}
