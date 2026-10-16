package storage

import "testing"

func TestSetRedisConfigMovesURLPasswordToSecret(t *testing.T) {
	cases := []struct {
		name, addr, password, wantAddr, wantPassword string
	}{
		{"bare addr", "10.0.0.5:6379", "pw", "10.0.0.5:6379", "pw"},
		{"url password moved out", "rediss://default:s3cr%40t@cache.example.com:6380/1", "", "rediss://default@cache.example.com:6380/1", "s3cr@t"},
		{"explicit password wins", "redis://:fromurl@host:6379", "explicit", "redis://host:6379", "explicit"},
		{"url without password", "redis://app@host:6379", "", "redis://app@host:6379", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			if err := db.SetRedisConfig(tc.addr, tc.password); err != nil {
				t.Fatal(err)
			}
			addr, password, err := db.GetRedisConfig()
			if err != nil || addr != tc.wantAddr || password != tc.wantPassword {
				t.Errorf("got %q %q %v, want %q %q", addr, password, err, tc.wantAddr, tc.wantPassword)
			}
		})
	}
}

func TestRateLimitRedis(t *testing.T) {
	db := openTestDB(t)
	if addr, _, _ := db.RateLimitRedis(); addr != "" {
		t.Errorf("no redis configured: %q", addr)
	}
	// Before ratelimit_backend existed, a stored address meant "use Redis".
	if err := db.SetRedisConfig("10.0.0.5:6379", "pw"); err != nil {
		t.Fatal(err)
	}
	if addr, pw, _ := db.RateLimitRedis(); addr != "10.0.0.5:6379" || pw != "pw" {
		t.Errorf("legacy fallback = %q %q", addr, pw)
	}
	if err := db.SetRateLimitBackend("memory"); err != nil {
		t.Fatal(err)
	}
	if addr, _, _ := db.RateLimitRedis(); addr != "" {
		t.Errorf("memory backend still returns %q", addr)
	}
	if err := db.SetRateLimitBackend("redis"); err != nil {
		t.Fatal(err)
	}
	if addr, _, _ := db.RateLimitRedis(); addr != "10.0.0.5:6379" {
		t.Errorf("redis backend = %q", addr)
	}

	k1, err := db.GetOrCreateRedisNamespaceKey()
	if err != nil || len(k1) != 32 {
		t.Fatalf("key = %x %v", k1, err)
	}
	if k2, _ := db.GetOrCreateRedisNamespaceKey(); string(k1) != string(k2) {
		t.Error("namespace key regenerated on second read")
	}
}
