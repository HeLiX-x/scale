package ipmanager

import (
	"errors"
	"fmt"
	"net"
)

func NewIPAllocator(baseBlock string, reservedBlocks []string) (*IPAllocator, error) {
	_, ipNet, err := net.ParseCIDR(baseBlock)
	if err != nil {
		return nil, fmt.Errorf("invalid base block: %v", err)
	}

	var reservedIpNets []*net.IPNet
	for _, block := range reservedBlocks {
		_, reservedIpNet, err := net.ParseCIDR(block)
		if err != nil {
			return nil, fmt.Errorf("invalid reserved block [%s]: %v", block, err)
		}
		reservedIpNets = append(reservedIpNets, reservedIpNet)
	}

	return &IPAllocator{
		baseIPNet:      ipNet,
		freedBlocks:    make(map[uint8][]string),
		reservedIPNets: reservedIpNets,
	}, nil
}

func (a *IPAllocator) AllocateCIDR(prefixLen uint8) (string, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if freed := a.freedBlocks[prefixLen]; len(freed) > 0 {
		block := freed[0]
		a.freedBlocks[prefixLen] = freed[1:]
		return block, nil
	}
	blockSize := uint32(1 << (32 - prefixLen))
	baseIPInt := ipToInt(a.baseIPNet.IP)
	candidateIPInt := baseIPInt
	if a.lastIPNet != nil {
		candidateIPInt = lastIpInBlockInt(a.lastIPNet) + 1
	}
	candidateIPInt = alignIpToBlockSize(candidateIPInt, baseIPInt, blockSize)
	for {
		candidateIP := intToIP(candidateIPInt)
		candidateNet := &net.IPNet{
			IP:   candidateIP,
			Mask: net.CIDRMask(int(prefixLen), 32),
		}
		candidateEndIP := intToIP(lastIpInBlockInt(candidateNet))
		if !a.baseIPNet.Contains(candidateIP) || !a.baseIPNet.Contains(candidateEndIP) {
			return "", errors.New("allocation exceeds base CIDR range")
		}
		skip := false
		for _, reservedIPNet := range a.reservedIPNets {
			if reservedIPNet.Contains(candidateIP) || reservedIPNet.Contains(candidateEndIP) {
				candidateIPInt = lastIpInBlockInt(reservedIPNet) + 1
				candidateIPInt = alignIpToBlockSize(candidateIPInt, baseIPInt, blockSize)
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		a.lastIPNet = candidateNet
		return candidateNet.String(), nil
	}
}

func (a *IPAllocator) ReleaseCIDR(block string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	_, ipNet, err := net.ParseCIDR(block)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR block %s: %v", block, err)
	}
	prefixLen, _ := ipNet.Mask.Size()
	if a.freedBlocks[uint8(prefixLen)] == nil {
		a.freedBlocks[uint8(prefixLen)] = []string{}
	}
	a.freedBlocks[uint8(prefixLen)] = append(a.freedBlocks[uint8(prefixLen)], block)
	return nil
}
