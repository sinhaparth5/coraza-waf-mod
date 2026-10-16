package ui

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestServiceRedisPanel(t *testing.T) {
	env := newAdminEnv(t)
	svc := env.seedService("shop", "shop.example.com")
	path := "/admin/services/redis/" + strconv.Itoa(svc.ID)

	// No connection yet: the panel points at Settings and enabling is a no-op.
	if rec := env.do("GET", path, nil); !strings.Contains(rec.Body.String(), "No Redis connection") {
		t.Errorf("unconfigured panel: %s", rec.Body)
	}
	env.do("POST", path, form("enabled", "1"))
	if got, _ := env.db.GetService(svc.ID); got.RedisMode != "" {
		t.Errorf("enabled without a connection: %q", got.RedisMode)
	}

	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	if rec := env.do("POST", "/admin/settings/redis", form("redis_addr", addr)); !strings.Contains(rec.Body.String(), "Saved") {
		t.Fatalf("save redis: %s", rec.Body)
	}
	rec := env.do("POST", path, form("enabled", "1"))
	if body := rec.Body.String(); !strings.Contains(body, "Isolated by Redis") || !strings.Contains(body, "palisade_shop:") || !strings.Contains(body, "shop:") {
		t.Fatalf("enabled panel: %s", body)
	}
	if got, _ := env.db.GetService(svc.ID); got.RedisMode != "acl" {
		t.Errorf("mode = %q", got.RedisMode)
	}

	// The connection can't be removed while a service still uses it.
	if rec := env.do("POST", "/admin/settings/redis", form("redis_addr", "")); !strings.Contains(rec.Body.String(), "shop") {
		t.Errorf("clear while in use: %s", rec.Body)
	}

	// Deleting the service removes its Redis login.
	env.do("DELETE", "/admin/services/"+strconv.Itoa(svc.ID), nil)
	c := redis.NewClient(&redis.Options{Addr: addr})
	defer c.Close()
	if err := c.Do(context.Background(), "ACL", "GETUSER", "palisade_shop").Err(); err != redis.Nil {
		t.Errorf("ACL user left after delete: %v", err)
	}
}
