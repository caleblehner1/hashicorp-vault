package main

import (
	"sync"
	"time"
)

// JWKSCache manages the lifecycle of JWKS keys with strict invalidation.
type JWKSCache struct {
	mu    sync.RWMutex
	keys  map[string]interface{}
	expiry time.Time
}

// Update replaces the entire cache with new keys, ensuring no stale keys persist.
func (c *JWKSCache) Update(newKeys map[string]interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = newKeys
	c.expiry = time.Now().Add(ttl)
}

// Get retrieves a key, returning nil if expired or not found.
func (c *JWKSCache) Get(kid string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if time.Now().After(c.expiry) {
		return nil, false
	}

	key, ok := c.keys[kid]
	return key, ok
}
