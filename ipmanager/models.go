package ipmanager

import (
	"net"
)

type IPAllocator struct {
	baseIPNet *net.IPNet
}
