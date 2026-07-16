package storage

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// TestBuildDSNEscapesSpecialCharacters is the core "bullet proof" guarantee
// of the Settings page's fields-based connection builder: a password
// containing characters that are meaningful in a DSN/URL (":", "@", "/")
// must round-trip through the driver's own DSN parser without corrupting
// where the parser thinks the host/database boundary is — the exact class
// of bug a fmt.Sprintf-based concatenation would introduce.
func TestBuildDSNEscapesSpecialCharacters(t *testing.T) {
	const nasty = `p@ss:word/with?special&chars=1`

	t.Run("mysql", func(t *testing.T) {
		dsn, err := BuildDSN(DBConnFields{
			Driver: "mysql", Host: "127.0.0.1", Port: "3307",
			Username: "root", Password: nasty, DBName: "mydb",
		})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			t.Fatalf("built DSN %q did not parse back: %v", dsn, err)
		}
		if cfg.Passwd != nasty {
			t.Errorf("password round-tripped as %q, want %q (dsn=%q)", cfg.Passwd, nasty, dsn)
		}
		if cfg.DBName != "mydb" {
			t.Errorf("dbname round-tripped as %q, want \"mydb\" (dsn=%q)", cfg.DBName, dsn)
		}
	})

	t.Run("postgres", func(t *testing.T) {
		dsn, err := BuildDSN(DBConnFields{
			Driver: "postgres", Host: "127.0.0.1", Port: "5433",
			Username: "postgres", Password: nasty, DBName: "mydb", SSLMode: "require",
		})
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("built DSN %q did not parse as a URL: %v", dsn, err)
		}
		gotPass, _ := u.User.Password()
		if gotPass != nasty {
			t.Errorf("password round-tripped as %q, want %q (dsn=%q)", gotPass, nasty, dsn)
		}
		if u.Path != "/mydb" {
			t.Errorf("path round-tripped as %q, want \"/mydb\" (dsn=%q)", u.Path, dsn)
		}
		if got := u.Query().Get("sslmode"); got != "require" {
			t.Errorf("sslmode = %q, want \"require\" (dsn=%q)", got, dsn)
		}
	})
}

func TestBuildDSNSQLite(t *testing.T) {
	dsn, err := BuildDSN(DBConnFields{Driver: "sqlite", Host: "/data/waf.db"})
	if err != nil {
		t.Fatal(err)
	}
	if dsn != "/data/waf.db" {
		t.Errorf("sqlite DSN = %q, want the path verbatim", dsn)
	}

	if _, err := BuildDSN(DBConnFields{Driver: "sqlite"}); err == nil {
		t.Error("empty sqlite path should error, got nil")
	}
}

func TestBuildDSNDefaultPorts(t *testing.T) {
	dsn, err := BuildDSN(DBConnFields{Driver: "mysql", Host: "db", Username: "root"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "tcp(db:3306)") {
		t.Errorf("mysql dsn = %q, want default port 3306", dsn)
	}

	dsn, err = BuildDSN(DBConnFields{Driver: "postgres", Host: "db", Username: "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "db:5432") {
		t.Errorf("postgres dsn = %q, want default port 5432", dsn)
	}
}

func TestBuildDSNExtraParams(t *testing.T) {
	dsn, err := BuildDSN(DBConnFields{
		Driver: "postgres", Host: "ep-example.neon.tech", Username: "neon", DBName: "neondb",
		SSLMode: "require", Extra: "connect_timeout=10&application_name=coraza",
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("connect_timeout"); got != "10" {
		t.Errorf("connect_timeout = %q, want \"10\"", got)
	}
	if got := u.Query().Get("application_name"); got != "coraza" {
		t.Errorf("application_name = %q, want \"coraza\"", got)
	}
}

func TestBuildDSNUnknownDriver(t *testing.T) {
	if _, err := BuildDSN(DBConnFields{Driver: "oracle"}); err == nil {
		t.Error("unknown driver should error, got nil")
	}
}

// TestDBConnConfigRoundtrip exercises the Settings-page persistence path:
// save, reload, and the "blank means keep existing" convention for the
// secret-bearing Password/DSN fields (matching EmailConfig.Token).
func TestDBConnConfigRoundtrip(t *testing.T) {
	db := openTestDB(t)

	cfg := DBConnConfig{
		Driver: "postgres", Mode: "fields", Host: "db.example.com", Port: "5432",
		Username: "app", Password: "s3cret", DBName: "waf", SSLMode: "require",
	}
	if err := db.SetDBConnConfig(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetDBConnConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got != cfg {
		t.Errorf("roundtrip = %+v, want %+v", got, cfg)
	}

	// Blank password/DSN on a subsequent save keeps the stored values.
	update := cfg
	update.Host = "db2.example.com"
	update.Password = ""
	update.DSN = ""
	if err := db.SetDBConnConfig(update); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetDBConnConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "db2.example.com" {
		t.Errorf("Host = %q, want updated value", got.Host)
	}
	if got.Password != "s3cret" {
		t.Errorf("Password = %q, want kept stored value", got.Password)
	}
}

// TestTestConnectionErrors covers the error paths that don't require a live
// database: an unknown driver, and a definitely-closed local port (fast,
// deterministic, no live MySQL/Postgres container needed in the default
// `go test ./...` run).
func TestTestConnectionErrors(t *testing.T) {
	if err := TestConnection("oracle", "whatever"); err == nil {
		t.Error("unknown driver should error, got nil")
	}

	dsn, err := BuildDSN(DBConnFields{Driver: "postgres", Host: "127.0.0.1", Port: "1", Username: "x", DBName: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := TestConnection("postgres", dsn); err == nil {
		t.Error("connection to a closed port should error, got nil")
	}
}
