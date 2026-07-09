package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBackend is a Redis-backed token-bucket limiter. It implements Backend
// and is safe to use across multiple WAF instances pointing at the same Redis.
// The token bucket logic runs as a Lua script so each Allow() is atomic.
type RedisBackend struct {
	client *redis.Client
	rate   float64
	burst  int
	script *redis.Script
}

// tokenBucketLua implements a token bucket in Redis.
// KEYS[1] = bucket key (e.g. "rl:1.2.3.4")
// ARGV[1] = rate (tokens/second, float)
// ARGV[2] = burst capacity (integer)
// ARGV[3] = current Unix timestamp in milliseconds
// Returns: {allowed (0/1), tokens_remaining (int), retry_after_ms (int)}
const tokenBucketLua = `
local key     = KEYS[1]
local rate    = tonumber(ARGV[1])
local burst   = tonumber(ARGV[2])
local now_ms  = tonumber(ARGV[3])
local now_sec = now_ms / 1000

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts     = tonumber(data[2])

if tokens == nil then
  tokens = burst
  ts     = now_sec
end

-- Refill tokens proportional to elapsed time.
local elapsed = math.max(0, now_sec - ts)
tokens = math.min(burst, tokens + elapsed * rate)

local allowed = 0
local retry_ms = 0

if tokens >= 1 then
  tokens  = tokens - 1
  allowed = 1
else
  retry_ms = math.ceil((1 - tokens) / rate * 1000)
end

-- TTL = time to fully refill the bucket from empty, plus a small buffer.
local ttl = math.ceil(burst / rate) + 2
redis.call('HMSET', key, 'tokens', tokens, 'ts', now_sec)
redis.call('EXPIRE', key, ttl)

return {allowed, math.floor(tokens), retry_ms}
`

// NewRedisBackend creates a RedisBackend connected to addr with the given
// password (empty = no auth). rate and burst match the same semantics as the
// in-memory Limiter.
func NewRedisBackend(addr, password string, rate float64, burst int) (*RedisBackend, error) {
	if addr == "" {
		return nil, fmt.Errorf("redis address must not be empty")
	}
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           0,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &RedisBackend{
		client: client,
		rate:   rate,
		burst:  burst,
		script: redis.NewScript(tokenBucketLua),
	}, nil
}

// Allow checks and consumes one token for ip. Satisfies Backend.
func (r *RedisBackend) Allow(ip string) Result {
	return r.allow(ip, r.rate, r.burst)
}

// AllowScaled behaves like Allow but against rate/burst multiplied by scale.
// Satisfies Backend. The Lua script already takes rate/burst as per-call
// arguments (see tokenBucketLua), so scaling needs no script change — just
// different numbers passed in for this one call.
func (r *RedisBackend) AllowScaled(ip string, scale float64) Result {
	if scale <= 0 {
		scale = 1.0
	}
	burst := int(float64(r.burst) * scale)
	if burst < 1 {
		burst = 1 // a scale bug must never fully lock out traffic
	}
	return r.allow(ip, r.rate*scale, burst)
}

func (r *RedisBackend) allow(ip string, rate float64, burst int) Result {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	key := "rl:" + ip
	nowMs := time.Now().UnixMilli()

	vals, err := r.script.Run(ctx, r.client, []string{key},
		rate, burst, nowMs).Int64Slice()
	if err != nil || len(vals) < 3 {
		// Redis unavailable or a malformed script reply — fail open to avoid
		// blocking legitimate traffic (indexing a short reply would panic).
		return Result{Allowed: true, Limit: rate, Burst: burst}
	}

	allowed := vals[0] == 1
	remaining := int(vals[1])
	retryMs := vals[2]

	if !allowed {
		return Result{
			Allowed:    false,
			RetryAfter: time.Duration(retryMs) * time.Millisecond,
			Remaining:  0,
			Limit:      rate,
			Burst:      burst,
		}
	}
	return Result{Allowed: true, Remaining: remaining, Limit: rate, Burst: burst}
}

// TrackedIPs returns the number of rate-limit keys currently stored in Redis.
// This is an approximation (DBSIZE counts all keys in the DB). Satisfies Backend.
func (r *RedisBackend) TrackedIPs() int {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	n, _ := r.client.DBSize(ctx).Result()
	return int(n)
}

// Stop closes the Redis connection. Satisfies Backend.
func (r *RedisBackend) Stop() { r.client.Close() }

// Ping tests the Redis connection. Used by the Settings page "Test connection" button.
func (r *RedisBackend) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return r.client.Ping(ctx).Err()
}

// PingRedis opens a one-shot connection to verify addr+password without
// creating a persistent backend. Returns nil on success.
func PingRedis(addr, password string) error {
	c := redis.NewClient(&redis.Options{
		Addr:        addr,
		Password:    password,
		DialTimeout: 3 * time.Second,
	})
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return c.Ping(ctx).Err()
}
