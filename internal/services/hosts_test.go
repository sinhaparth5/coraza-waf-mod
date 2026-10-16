package services

import (
	"context"
	"testing"

	"palisade/internal/storage"
)

func TestValidateHosts(t *testing.T) {
	others := []storage.Service{
		{ID: 1, Name: "self", Host: "example.com", HostAliases: []string{"old.example.com"}},
		{ID: 2, Name: "blog", Host: "blog.example.com", HostAliases: []string{"news.example.com"}},
	}
	cases := []struct {
		name          string
		host          string
		aliases       []string
		canonical     string
		wantAliases   int
		wantCanonical string
		wantErr       bool
	}{
		{"www alias", "example.com", []string{"WWW.Example.com", ""}, "", 1, "", false},
		{"redirect to alias", "example.com", []string{"www.example.com"}, "www.example.com", 1, "www.example.com", false},
		{"redirect to host", "example.com", []string{"www.example.com"}, "Example.com", 1, "example.com", false},
		{"own old alias reusable", "example.com", []string{"old.example.com"}, "", 1, "", false},
		{"alias taken by other host", "example.com", []string{"blog.example.com"}, "", 0, "", true},
		{"alias taken by other alias", "example.com", []string{"news.example.com"}, "", 0, "", true},
		{"alias repeats host", "example.com", []string{"example.com"}, "", 0, "", true},
		{"alias twice", "example.com", []string{"www.example.com", "www.example.com"}, "", 0, "", true},
		{"not a hostname", "example.com", []string{"www.example.com/path"}, "", 0, "", true},
		{"wildcard", "example.com", []string{"*.example.com"}, "", 0, "", true},
		{"canonical not listed", "example.com", []string{"www.example.com"}, "other.com", 0, "", true},
		{"host taken", "blog.example.com", nil, "", 0, "", true},
		{"prefix service with aliases", "", []string{"www.example.com"}, "", 0, "", true},
		{"prefix service, nothing set", "", nil, "", 0, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			aliases, canonical, err := ValidateHosts(1, tc.host, tc.aliases, tc.canonical, others)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(aliases) != tc.wantAliases || canonical != tc.wantCanonical {
				t.Errorf("got %v %q, want %d aliases, canonical %q", aliases, canonical, tc.wantAliases, tc.wantCanonical)
			}
		})
	}
}

func TestRegistryHostAliases(t *testing.T) {
	db := openTestDB(t)
	if err := db.AddService("site", "example.com", "", "http://10.0.0.5:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, _ := db.ListServices()
	if err := db.SetServiceHosts(list[0].ID, []string{"www.example.com"}, "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetServiceTLS(list[0].ID, "auto", "", "", ""); err != nil {
		t.Fatal(err)
	}
	reg, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"example.com", "www.example.com", "WWW.example.com:8443"} {
		if s := reg.Match(host, "/"); s == nil || s.Name != "site" {
			t.Errorf("Match(%q) = %v, want site", host, s)
		}
		if !reg.IsServiceHost(host) {
			t.Errorf("IsServiceHost(%q) = false", host)
		}
	}
	if s := reg.Match("api.example.com", "/"); s != nil {
		t.Errorf("Match(unrelated) = %q, want nil", s.Name)
	}
	if err := reg.HostPolicy()(context.Background(), "www.example.com"); err != nil {
		t.Errorf("HostPolicy refused the alias: %v", err)
	}
}
