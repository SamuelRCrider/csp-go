package llm

import (
	"sync"
	"time"
)

// RateLimiter implements rate limiting functionality for SOC 2 compliance
type RateLimiter struct {
	// Map to track request counts by key (user ID, IP, etc.)
	counters     map[string]*RateLimitEntry
	mu           sync.Mutex
	maxRequests  int           // Maximum requests per window
	windowPeriod time.Duration // Time window for rate limiting
}

// RateLimitEntry represents an entry in the rate limit counter
type RateLimitEntry struct {
	Count       int       // Number of requests in current window
	WindowStart time.Time // Start time of current window
}

// NewRateLimiter creates a new rate limiter with the specified configuration
func NewRateLimiter(maxRequests int, windowPeriod time.Duration) *RateLimiter {
	return &RateLimiter{
		counters:     make(map[string]*RateLimitEntry),
		maxRequests:  maxRequests,
		windowPeriod: windowPeriod,
	}
}

// CheckLimit checks if the rate limit for the given key has been exceeded
func (r *RateLimiter) CheckLimit(key string) (bool, int, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	entry, ok := r.counters[key]

	// If no entry exists or window has expired, create new entry
	if !ok || now.Sub(entry.WindowStart) > r.windowPeriod {
		r.counters[key] = &RateLimitEntry{
			Count:       1,
			WindowStart: now,
		}
		return false, 1, now.Add(r.windowPeriod)
	}

	// Increment counter
	entry.Count++

	// Check if rate limit exceeded
	if entry.Count > r.maxRequests {
		// Return true (limit exceeded), current count, and reset time
		return true, entry.Count, entry.WindowStart.Add(r.windowPeriod)
	}

	return false, entry.Count, entry.WindowStart.Add(r.windowPeriod)
}
