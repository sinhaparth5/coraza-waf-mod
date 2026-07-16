package storage

import "testing"

func TestResolveDialect(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "sqlite"},
		{"sqlite", "sqlite"},
		{"SQLite", "sqlite"},
		{"mysql", "mysql"},
		{"mariadb", "mysql"},
		{"MariaDB", "mysql"},
		{"postgres", "postgres"},
		{"postgresql", "postgres"},
		{"cockroachdb", "postgres"},
		{"cockroach", "postgres"},
		{"neon", "postgres"},
		{"  postgres  ", "postgres"},
	}
	for _, tc := range cases {
		d, err := resolveDialect(tc.in)
		if err != nil {
			t.Errorf("resolveDialect(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if d.name != tc.want {
			t.Errorf("resolveDialect(%q).name = %q, want %q", tc.in, d.name, tc.want)
		}
	}
}

func TestResolveDialectUnknown(t *testing.T) {
	if _, err := resolveDialect("carrier-pigeon"); err == nil {
		t.Fatal("resolveDialect with an unknown driver name should error, got nil")
	}
}

func TestDialectAutoIncrementPK(t *testing.T) {
	cases := []struct {
		d    dialect
		want string
	}{
		{dialectSQLite, "INTEGER PRIMARY KEY AUTOINCREMENT"},
		{dialectMySQL, "INTEGER PRIMARY KEY AUTO_INCREMENT"},
		{dialectPostgres, "INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY"},
	}
	for _, tc := range cases {
		if got := tc.d.autoIncrementPK(); got != tc.want {
			t.Errorf("%s.autoIncrementPK() = %q, want %q", tc.d.name, got, tc.want)
		}
	}
}

func TestDialectAddColumnIfNotExists(t *testing.T) {
	cases := []struct {
		d    dialect
		want string
	}{
		{dialectSQLite, "ALTER TABLE requests ADD COLUMN foo TEXT"},
		{dialectMySQL, "ALTER TABLE requests ADD COLUMN IF NOT EXISTS foo TEXT"},
		{dialectPostgres, "ALTER TABLE requests ADD COLUMN IF NOT EXISTS foo TEXT"},
	}
	for _, tc := range cases {
		if got := tc.d.addColumnIfNotExists("requests", "foo TEXT"); got != tc.want {
			t.Errorf("%s.addColumnIfNotExists() = %q, want %q", tc.d.name, got, tc.want)
		}
	}
}
