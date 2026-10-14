package mailer

import (
	"path/filepath"
	"slices"
	"testing"

	"palisade/internal/storage"
)

func TestSendRejectsIncompleteConfig(t *testing.T) {
	for _, cfg := range []storage.EmailConfig{
		{To: "", Token: "t"},
		{To: "a@b.c", Token: ""},
		{To: " , ,", Token: "t"},
	} {
		if err := Send(cfg, "s", "t", "h"); err == nil {
			t.Errorf("Send(%+v) should fail before dialing", cfg)
		}
	}
}

func TestSplitAddrs(t *testing.T) {
	if got := splitAddrs(" a@x.test, ,b@x.test ,"); !slices.Equal(got, []string{"a@x.test", "b@x.test"}) {
		t.Errorf("splitAddrs = %v", got)
	}
}

func TestReporterStartStop(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := NewReporter(db) // email disabled: the startup pass is a no-op
	r.Stop()
	r.Stop() // idempotent
}
