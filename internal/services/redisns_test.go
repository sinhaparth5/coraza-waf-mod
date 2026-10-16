package services

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestRedisNamespaceURL(t *testing.T) {
	key := []byte("k")
	pw := redisPassword(key, "shop")
	cases := []struct {
		name, addr, password, mode, want string
	}{
		{"acl, bare addr", "10.0.0.5:6379", "", RedisModeACL, "redis://palisade_shop:" + pw + "@10.0.0.5:6379"},
		{"acl keeps tls and db", "rediss://default@cache.example.com:6380/2", "secret", RedisModeACL, "rediss://palisade_shop:" + pw + "@cache.example.com:6380/2"},
		{"prefix shares palisade's login", "rediss://app@cache.example.com:6380", "secret", RedisModePrefix, "rediss://app:secret@cache.example.com:6380"},
		{"prefix, password only", "10.0.0.5:6379", "secret", RedisModePrefix, "redis://:secret@10.0.0.5:6379"},
		{"prefix, no auth", "10.0.0.5:6379", "", RedisModePrefix, "redis://10.0.0.5:6379"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns, err := Namespace(tc.addr, tc.password, key, "shop", tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			if ns.URL != tc.want || ns.Prefix != "shop:" {
				t.Errorf("got %q %q, want %q", ns.URL, ns.Prefix, tc.want)
			}
		})
	}
	if redisPassword(key, "shop") == redisPassword(key, "blog") || redisPassword(key, "shop") != pw {
		t.Error("passwords must be stable per service and differ between services")
	}
}

func TestProvisionRedisRejectsGlobNames(t *testing.T) {
	for _, name := range []string{"shop*", "a?b", "x[1]", `a\b`, "my shop", ""} {
		// Unreachable address: the name check must fail before any dial.
		if _, err := ProvisionRedis(context.Background(), "127.0.0.1:1", "", []byte("k"), name); err == nil || !strings.Contains(err.Error(), "may only contain") {
			t.Errorf("%q: err = %v", name, err)
		}
	}
}

// TestRedisNamespaceIsolationLive checks the ACL rules against a real
// server: each app reaches only its own prefix, and deprovisioning locks
// it out. Set TEST_REDIS_ADDR to a Redis 6+ whose default user may run ACL.
func TestRedisNamespaceIsolationLive(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	key := []byte("test-key")
	for _, name := range []string{"shop", "blog"} {
		mode, err := ProvisionRedis(ctx, addr, "", key, name)
		if err != nil || mode != RedisModeACL {
			t.Fatalf("provision %s = %q, %v", name, mode, err)
		}
		t.Cleanup(func() { _ = DeprovisionRedis(ctx, addr, "", name) })
	}
	app := func(name string) *redis.Client {
		ns, err := Namespace(addr, "", key, name, RedisModeACL)
		if err != nil {
			t.Fatal(err)
		}
		opts, err := redis.ParseURL(ns.URL)
		if err != nil {
			t.Fatal(err)
		}
		c := redis.NewClient(opts)
		t.Cleanup(func() { c.Close() })
		return c
	}
	shop, blog := app("shop"), app("blog")

	if err := shop.Set(ctx, "shop:session:1", "alice", 0).Err(); err != nil {
		t.Fatalf("own prefix: %v", err)
	}
	if err := shop.Get(ctx, "blog:session:1").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("other prefix read: %v", err)
	}
	if err := blog.Get(ctx, "shop:session:1").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("blog read shop's session: %v", err)
	}
	if err := shop.FlushAll(ctx).Err(); err == nil {
		t.Error("FLUSHALL allowed for an app user")
	}
	if err := shop.Publish(ctx, "blog:events", "x").Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Errorf("publish to other prefix: %v", err)
	}

	// A Redis restart drops the users; one reconcile pass puts them back.
	admin := redis.NewClient(&redis.Options{Addr: addr})
	defer admin.Close()
	admin.Do(ctx, "ACL", "DELUSER", redisUser("shop"))
	c, _ := redisClient(addr, "")
	defer c.Close()
	if err := c.Do(ctx, "ACL", "GETUSER", redisUser("shop")).Err(); err != redis.Nil {
		t.Fatalf("GETUSER on a missing user = %v, want redis.Nil (reconcile relies on it)", err)
	}
	if err := setUser(ctx, c, key, "shop"); err != nil {
		t.Fatal(err)
	}
	if err := app("shop").Get(ctx, "shop:session:1").Err(); err != nil {
		t.Errorf("after re-create, same derived password: %v", err)
	}

	if err := DeprovisionRedis(ctx, addr, "", "shop"); err != nil {
		t.Fatal(err)
	}
	if err := app("shop").Ping(ctx).Err(); err == nil {
		t.Error("deprovisioned user can still log in")
	}
}

// TestProvisionRedisFallsBackToPrefixLive: a connection user without ACL
// rights (like hosted Redis that blocks ACL) gets prefix mode, not an error.
func TestProvisionRedisFallsBackToPrefixLive(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	admin := redis.NewClient(&redis.Options{Addr: addr})
	defer admin.Close()
	if err := admin.Do(ctx, "ACL", "SETUSER", "limited", "reset", "on", ">pw", "~*", "+@all", "-@admin").Err(); err != nil {
		t.Fatal(err)
	}
	defer admin.Do(ctx, "ACL", "DELUSER", "limited")

	mode, err := ProvisionRedis(ctx, "redis://limited@"+addr, "pw", []byte("k"), "shop")
	if err != nil || mode != RedisModePrefix {
		t.Errorf("mode = %q, err = %v, want prefix", mode, err)
	}
}
