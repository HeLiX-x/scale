package ipmanager

import (
	"encoding/binary"
	"fmt"
	"net"
)

func ipToInt(ip net.IP) (uint32, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("invalid IP address")
	}
	return binary.BigEndian.Uint32(ip4), nil
}

func intToIP(ipInt uint32) net.IP {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, ipInt)
	return net.IP(buf)
}

func lastIpInBlockInt(block *net.IPNet) uint32 {
	prefixLength, _ := block.Mask.Size()
	capacity := 1 << (32 - prefixLength)

	ipInt, err := ipToInt(block.IP)
	if err != nil {
		return 0 // or handle error differently
	}
	return ipInt + uint32(capacity) - 1
}

func alignIpToBlockSize(ip, base, size uint32) uint32 {
	if size == 0 {
		return base
	}
	offset := ip - base
	roundedOffset := ((offset + size - 1) / size) * size
	return base + roundedOffset
}
