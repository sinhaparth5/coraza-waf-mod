package storage

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
)

// openTestDB is the single entry point every internal/storage test file uses
// to get a DB handle, replacing the old direct
// Open(filepath.Join(t.TempDir(), "test.db")) call at all ~26 call sites.
//
// By default (no env vars set) it behaves exactly as before: a fresh SQLite
// file in a t.TempDir(), so `go test ./...` stays hermetic and needs no
// Docker/network access. Setting TEST_DB_DRIVER ("mysql"/"mariadb" or
// "postgres"/"postgresql"/"cockroachdb"/"neon") plus TEST_DB_DSN (an
// admin-level connection string able to CREATE/DROP DATABASE — see
// docker-compose.test.yml and ci.yml for the exact values used against the
// local/CI containers) redirects every existing test to run the identical
// assertions against a real MySQL or Postgres server instead, giving each
// test its own throwaway database so tests don't see each other's rows the
// way they would sharing one persistent server-backed database.
func openTestDB(t *testing.T) *DB {
	t.Helper()

	driver := strings.ToLower(strings.TrimSpace(os.Getenv("TEST_DB_DRIVER")))
	if driver == "" || driver == "sqlite" {
		db, err := Open(filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatalf("open sqlite test db: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}

	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Fatalf("TEST_DB_DRIVER=%s set but TEST_DB_DSN is empty", driver)
	}

	testDSN, cleanupDB := createTestDatabase(t, driver, dsn)
	db, err := OpenWithDriver(driver, testDSN)
	if err != nil {
		cleanupDB()
		t.Fatalf("open %s test db: %v", driver, err)
	}
	t.Cleanup(func() {
		db.Close()
		cleanupDB()
	})
	return db
}

// createTestDatabase creates a uniquely-named database on the server
// identified by adminDSN and returns a DSN pointing at it plus a cleanup
// func that drops it. Isolation is per-database rather than per-table
// because several existing tests assert on whole-table state (e.g.
// "empty table counts = (0, 0)" in TestCountIPRulesByType) that a shared,
// ever-growing database across the whole test binary would break.
func createTestDatabase(t *testing.T, driver, adminDSN string) (testDSN string, cleanup func()) {
	t.Helper()

	d, err := resolveDialect(driver)
	if err != nil {
		t.Fatalf("resolve dialect %q: %v", driver, err)
	}

	admin, err := sqlx.Open(d.driverName, adminDSN)
	if err != nil {
		t.Fatalf("connect admin %s: %v", d.name, err)
	}
	if err := admin.Ping(); err != nil {
		admin.Close()
		t.Fatalf("ping admin %s (is docker-compose.test.yml up?): %v", d.name, err)
	}

	dbName := fmt.Sprintf("cwaf_test_%d", time.Now().UnixNano())

	switch d.name {
	case "mysql":
		if _, err := admin.Exec("CREATE DATABASE " + dbName); err != nil {
			admin.Close()
			t.Fatalf("create mysql test database %s: %v", dbName, err)
		}
		// adminDSN is expected to end in "/" with no database selected
		// (e.g. "root:root@tcp(127.0.0.1:3307)/") — go-sql-driver/mysql's
		// DSN format is just <prefix>/<dbname>, so appending the name is
		// enough to select it.
		testDSN = adminDSN + dbName
	case "postgres":
		if _, err := admin.Exec("CREATE DATABASE " + dbName); err != nil {
			admin.Close()
			t.Fatalf("create postgres test database %s: %v", dbName, err)
		}
		u, err := url.Parse(adminDSN)
		if err != nil {
			admin.Close()
			t.Fatalf("parse postgres admin dsn: %v", err)
		}
		u.Path = "/" + dbName
		testDSN = u.String()
	default:
		admin.Close()
		t.Fatalf("createTestDatabase: unsupported driver %q", driver)
	}

	cleanup = func() {
		defer admin.Close()
		var dropSQL string
		switch d.name {
		case "mysql":
			dropSQL = "DROP DATABASE IF EXISTS " + dbName
		case "postgres":
			// WITH (FORCE) (Postgres 13+, present on the postgres:16 test
			// image) disconnects any lingering pooled connections instead
			// of DROP DATABASE erroring "database is being accessed by
			// other users" — db.Close() above should have already closed
			// them, but this closes a race rather than assuming it.
			dropSQL = "DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)"
		}
		if _, err := admin.Exec(dropSQL); err != nil {
			t.Logf("cleanup: drop test database %s: %v", dbName, err)
		}
	}
	return testDSN, cleanup
}
