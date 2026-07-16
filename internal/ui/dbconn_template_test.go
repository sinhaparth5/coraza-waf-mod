package ui

import (
	"bytes"
	"strings"
	"testing"
)

// TestDBConnCardRenders executes the Settings-page "Database connection"
// card standalone (the same partial SaveDBConnConfig re-renders) so a
// renamed field or broken pipeline fails here instead of at first click in
// the UI. Covers all three driver states since the card's markup branches
// heavily on which one is selected (sqlite hides the external-connection
// fields entirely; mysql/postgres show different SSL-mode option sets).
func TestDBConnCardRenders(t *testing.T) {
	h := &Handler{}
	if err := h.parseTemplates(); err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	cases := []struct {
		name string
		data map[string]any
		want []string
		gone []string
	}{
		{
			name: "sqlite",
			data: map[string]any{
				"AdminPath": "/admin", "ActiveDBDriver": "sqlite", "ActiveDBPath": "waf.db",
				"DBConnDriver": "sqlite", "DBConnHost": "waf.db",
			},
			want: []string{"/admin/settings/dbconn", `value="waf.db"`, "Currently running", "sqlite"},
			gone: []string{"Redis"}, // sanity: not accidentally sharing the ratelimit card's content
		},
		{
			name: "mysql-fields",
			data: map[string]any{
				"AdminPath": "/admin", "ActiveDBDriver": "sqlite", "ActiveDBPath": "waf.db",
				"DBConnDriver": "mysql", "DBConnMode": "fields", "DBConnHost": "db", "DBConnPort": "3306",
				"DBConnUsername": "root", "DBConnDBName": "coraza", "DBConnSSLMode": "true",
			},
			want: []string{
				`value="db"`, `value="3306"`, `value="root"`, `value="coraza"`,
				`id="dbconn_sslmode_mysql"`, `/admin/settings/dbconn/test`,
			},
		},
		{
			name: "postgres-dsn",
			data: map[string]any{
				"AdminPath": "/admin", "ActiveDBDriver": "sqlite", "ActiveDBPath": "waf.db",
				"DBConnDriver": "postgres", "DBConnMode": "dsn", "DBConnDSNSet": true,
			},
			want: []string{"saved; leave blank to keep", `name="dbconn_dsn"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := h.tmpls["settings"].ExecuteTemplate(&buf, "dbconn-card", tc.data); err != nil {
				t.Fatalf("execute dbconn-card: %v", err)
			}
			out := buf.String()
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("[%s] dbconn-card output missing %q", tc.name, want)
				}
			}
			for _, gone := range tc.gone {
				if strings.Contains(out, gone) {
					t.Errorf("[%s] dbconn-card output unexpectedly contains %q", tc.name, gone)
				}
			}
		})
	}
}
