package storage

import "testing"

// TestSetServiceSchemaRoundtrip exercises SetServiceSchema/GetService for the
// request-schema validation feature (issue #75) — waf.Engine.SetRequestSchema
// reads Service.RequestSchema/SchemaMode off the same row this writes.
func TestSetServiceSchemaRoundtrip(t *testing.T) {
	db := openTestDB(t)

	if err := db.AddService("app", "app.example.com", "", "http://127.0.0.1:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListServices()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	if list[0].SchemaMode != "off" || list[0].RequestSchema != "" {
		t.Fatalf("new service schema state = %+v, want mode=off and empty schema", list[0])
	}

	const schema = `{"type":"object","required":["email"]}`
	if err := db.SetServiceSchema(list[0].ID, schema, "enforce"); err != nil {
		t.Fatal(err)
	}
	svc, err := db.GetService(list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if svc.RequestSchema != schema || svc.SchemaMode != "enforce" {
		t.Fatalf("after SetServiceSchema: RequestSchema=%q SchemaMode=%q, want %q/enforce", svc.RequestSchema, svc.SchemaMode, schema)
	}
}

// TestSetServiceSchemaNormalizesUnknownMode mirrors the webhook
// destination_type precedent: an unrecognized mode is normalized to the
// safe, non-blocking "off" rather than persisted as-is, and a schema saved
// with no mode (or an empty schema saved with a mode) never leaves the row
// silently enforcing.
func TestSetServiceSchemaNormalizesUnknownMode(t *testing.T) {
	db := openTestDB(t)

	if err := db.AddService("app", "app.example.com", "", "http://127.0.0.1:3000", 0, 0); err != nil {
		t.Fatal(err)
	}
	list, err := db.ListServices()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	id := list[0].ID

	if err := db.SetServiceSchema(id, `{"type":"object"}`, "strict"); err != nil {
		t.Fatal(err)
	}
	svc, err := db.GetService(id)
	if err != nil {
		t.Fatal(err)
	}
	if svc.SchemaMode != "off" {
		t.Errorf("SetServiceSchema with unknown mode persisted %q, want normalized to off", svc.SchemaMode)
	}

	if err := db.SetServiceSchema(id, "", "enforce"); err != nil {
		t.Fatal(err)
	}
	svc, err = db.GetService(id)
	if err != nil {
		t.Fatal(err)
	}
	if svc.SchemaMode != "off" {
		t.Errorf("SetServiceSchema with an empty schema persisted mode %q, want off", svc.SchemaMode)
	}
}
