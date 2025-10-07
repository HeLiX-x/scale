// In ipmanager/services.go

package ipmanager

import (
	"fmt"
	"net"
	"scale/database" // Import the database package to access the Redis client
)

// The Redis key where the set of available IPs will be stored.
const ipPoolKey = "ip_pool:available"

// NewIPAllocator now initializes the IP pool in Redis if it doesn't exist.
func NewIPAllocator(baseBlock string) (*IPAllocator, error) {
	_, ipNet, err := net.ParseCIDR(baseBlock)
	if err != nil {
		return nil, fmt.Errorf("invalid base block: %v", err)
	}

	// Check if the IP pool is already initialized in Redis.
	poolExists, err := database.Rdb.Exists(database.Ctx, ipPoolKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check redis for ip pool: %w", err)
	}

	// If the pool doesn't exist, create it.
	if poolExists == 0 {
		fmt.Println("IP pool not found in Redis, initializing...")
		firstIP, _ := ipToInt(ipNet.IP)
		// Note: We skip the network and broadcast addresses.
		lastIP := lastIpInBlockInt(ipNet) - 1
		firstUsableIP := firstIP + 1

		// Use a pipeline for efficiency to add all IPs at once.
		pipe := database.Rdb.Pipeline()
		for i := firstUsableIP; i <= lastIP; i++ {
			ipStr := intToIP(i).String()
			pipe.SAdd(database.Ctx, ipPoolKey, ipStr)
		}
		if _, err := pipe.Exec(database.Ctx); err != nil {
			return nil, fmt.Errorf("failed to populate ip pool in redis: %w", err)
		}
		fmt.Printf("Successfully initialized IP pool with %d addresses.\n", (lastIP - firstUsableIP + 1))
	} else {
		fmt.Println("IP pool already initialized in Redis.")
	}

	return &IPAllocator{
		baseIPNet: ipNet,
	}, nil
}

// AllocateCIDR now atomically pops an IP from the Redis set.
// It's now safe to be called from multiple server instances at the same time.
func (a *IPAllocator) AllocateCIDR(prefixLen uint8) (string, error) {
	// SPOP is an atomic operation that randomly removes and returns a member from a set.
	ip, err := database.Rdb.SPop(database.Ctx, ipPoolKey).Result()
	if err != nil {
		return "", fmt.Errorf("failed to allocate IP from pool: %w", err)
	}

	// Return the IP with the correct CIDR notation.
	return fmt.Sprintf("%s/%d", ip, prefixLen), nil
}

// ReleaseCIDR adds an IP back to the Redis set.
// This is also a thread-safe and multi-instance-safe operation.
func (a *IPAllocator) ReleaseCIDR(block string) error {
	// Parse the IP from the CIDR string (e.g., "100.64.0.5/32")
	ip, _, err := net.ParseCIDR(block)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR block %s: %v", block, err)
	}

	// SAdd adds the IP back to the set of available addresses.
	// If the IP is already in the set, this command does nothing.
	_, err = database.Rdb.SAdd(database.Ctx, ipPoolKey, ip.String()).Result()
	if err != nil {
		return fmt.Errorf("failed to release ip back to pool: %w", err)
	}
	return nil
}
