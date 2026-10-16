package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"palisade/internal/security/ratelimit"
	"palisade/internal/storage"
)

// Per-service Redis namespaces (issue #124): several backend apps share the
// one Redis configured on the Settings page for their own sessions, each
// confined to keys (and pub/sub channels) starting with "<service name>:".
//
// Where the server allows it, the confinement is a Redis ACL user that can
// touch nothing else ("acl" mode), so a bug in one app can't read another's
// sessions. Hosted Redis that refuses ACL SETUSER (e.g. Upstash), or a
// connection user without ACL rights, gets "prefix" mode: the same prefix,
// Palisade's own credentials, isolation by convention only.
//
// Passwords are derived, never stored: HMAC(redis_ns_key, service name), so
// the URL can be shown again at any time and re-provisioning after a Redis
// restart needs no extra state.

const (
	RedisModeACL    = "acl"
	RedisModePrefix = "prefix"
)

// RedisNamespace is what a service's app needs to use its namespace.
type RedisNamespace struct {
	Mode   string
	URL    string // connection URL, credentials included
	Prefix string // every key and channel must start with this
}

func redisPrefix(name string) string { return name + ":" }
func redisUser(name string) string   { return "palisade_" + name }

func redisPassword(key []byte, name string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("redis-namespace\x00" + name))
	return hex.EncodeToString(mac.Sum(nil))
}

// setUser creates or replaces name's ACL user. "reset" first, so rules left
// over from an older Palisade can't widen what the user may do. -@dangerous
// drops KEYS, FLUSHALL, CONFIG, DEBUG and friends; the key and channel
// patterns are what actually fence the app in.
func setUser(ctx context.Context, c *redis.Client, key []byte, name string) error {
	p := redisPrefix(name)
	return c.Do(ctx, "ACL", "SETUSER", redisUser(name), "reset", "on",
		">"+redisPassword(key, name), "~"+p+"*", "&"+p+"*",
		"+@all", "-@admin", "-@dangerous").Err()
}

func redisClient(addr, password string) (*redis.Client, error) {
	opts, err := ratelimit.RedisOptions(addr, password)
	if err != nil {
		return nil, err
	}
	opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout = 3*time.Second, 2*time.Second, 2*time.Second
	return redis.NewClient(opts), nil
}

// ProvisionRedis sets up name's namespace and returns the mode it got:
// "acl" when Redis accepted the ACL user, else "prefix". It fails only when
// Redis is unreachable or the name could widen the key pattern.
func ProvisionRedis(ctx context.Context, addr, password string, key []byte, name string) (string, error) {
	// The name ends up inside a key glob: *, ?, [ or \ would widen it.
	if !safeServiceNameForBan.MatchString(name) {
		return "", fmt.Errorf("service name %q may only contain letters, digits, '.', '_' and '-' to get a Redis namespace", name)
	}
	c, err := redisClient(addr, password)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if err := c.Ping(ctx).Err(); err != nil {
		return "", fmt.Errorf("redis: %w", err)
	}
	if err := setUser(ctx, c, key, name); err != nil {
		log.Printf("redis namespace [%s]: ACL unavailable, using prefix mode: %v", name, err)
		return RedisModePrefix, nil
	}
	return RedisModeACL, nil
}

// DeprovisionRedis removes name's ACL user, which also disconnects any app
// still using it. Keys under the prefix are left alone: they are the app's
// data, not Palisade's.
func DeprovisionRedis(ctx context.Context, addr, password, name string) error {
	c, err := redisClient(addr, password)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Do(ctx, "ACL", "DELUSER", redisUser(name)).Err()
}

// Namespace builds the connection details to hand to name's app. The host
// is the address Palisade itself uses, which an app on another network may
// need to swap for its own.
func Namespace(addr, password string, key []byte, name, mode string) (RedisNamespace, error) {
	opts, err := ratelimit.RedisOptions(addr, password)
	if err != nil {
		return RedisNamespace{}, err
	}
	u := url.URL{Scheme: "redis", Host: opts.Addr}
	if opts.TLSConfig != nil {
		u.Scheme = "rediss"
	}
	switch {
	case mode == RedisModeACL:
		u.User = url.UserPassword(redisUser(name), redisPassword(key, name))
	case opts.Password != "":
		u.User = url.UserPassword(opts.Username, opts.Password)
	}
	if opts.DB != 0 {
		u.Path = "/" + strconv.Itoa(opts.DB)
	}
	return RedisNamespace{Mode: mode, URL: u.String(), Prefix: redisPrefix(name)}, nil
}

// RunRedisReconcile re-creates missing ACL users every interval, forever.
// ACL SETUSER lives in Redis memory only, so without this a Redis restart
// (one with no aclfile) would lock every app out until someone re-saved
// its service. Existing users are left untouched, so a tick costs one
// ACL GETUSER per acl-mode service and never disturbs live connections.
func RunRedisReconcile(db *storage.DB, interval time.Duration) {
	for {
		if err := ReconcileRedis(context.Background(), db); err != nil {
			log.Printf("redis namespaces: %v", err)
		}
		time.Sleep(interval)
	}
}

// ReconcileRedis runs one reconcile pass; see RunRedisReconcile.
func ReconcileRedis(ctx context.Context, db *storage.DB) error {
	list, err := db.ListServices()
	if err != nil {
		return err
	}
	var acl []string
	for _, s := range list {
		if s.RedisMode == RedisModeACL {
			acl = append(acl, s.Name)
		}
	}
	if len(acl) == 0 {
		return nil
	}
	addr, password, err := db.GetRedisConfig()
	if err != nil || addr == "" {
		return err
	}
	key, err := db.GetOrCreateRedisNamespaceKey()
	if err != nil {
		return err
	}
	c, err := redisClient(addr, password)
	if err != nil {
		return err
	}
	defer c.Close()
	for _, name := range acl {
		err := c.Do(ctx, "ACL", "GETUSER", redisUser(name)).Err()
		if errors.Is(err, redis.Nil) {
			log.Printf("redis namespace [%s]: ACL user missing (Redis restarted?), re-creating", name)
			err = setUser(ctx, c, key, name)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}
