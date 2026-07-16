package storage

import (
	"testing"
)

// TestAPIKeyRoundtrip exercises create/list/validate/revoke for the api_keys
// table backing the REST API's bearer-token auth (see ui/api.go).
func TestAPIKeyRoundtrip(t *testing.T) {
	db := openTestDB(t)

	const hash = "deadbeef00000000000000000000000000000000000000000000000000000000"
	id, err := db.CreateAPIKey("ci-deploy", "cwaf_ab12cd34", hash)
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("CreateAPIKey returned id 0")
	}

	keys, err := db.ListAPIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Name != "ci-deploy" || keys[0].Prefix != "cwaf_ab12cd34" {
		t.Fatalf("ListAPIKeys() = %+v, want one ci-deploy key", keys)
	}
	if keys[0].LastUsedAt != nil {
		t.Errorf("LastUsedAt = %v, want nil before first use", keys[0].LastUsedAt)
	}

	got, err := db.ValidateAPIKey(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != id {
		t.Fatalf("ValidateAPIKey(correct hash) = %+v, want id %d", got, id)
	}

	miss, err := db.ValidateAPIKey("not-a-real-hash")
	if err != nil {
		t.Fatal(err)
	}
	if miss != nil {
		t.Fatalf("ValidateAPIKey(wrong hash) = %+v, want nil (not an error)", miss)
	}

	if err := db.TouchAPIKey(id); err != nil {
		t.Fatal(err)
	}
	got, err = db.ValidateAPIKey(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastUsedAt == nil {
		t.Error("LastUsedAt still nil after TouchAPIKey")
	}

	if err := db.RemoveAPIKey(id); err != nil {
		t.Fatal(err)
	}
	got, err = db.ValidateAPIKey(hash)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("ValidateAPIKey after revoke = %+v, want nil", got)
	}
	keys, err = db.ListAPIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("ListAPIKeys after revoke = %+v, want empty", keys)
	}
}
