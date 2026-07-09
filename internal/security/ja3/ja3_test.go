package ja3

import "testing"

func TestStoreGetDelete(t *testing.T) {
	remoteAddr := "192.0.2.10:54321"
	hash := "0123456789abcdef0123456789abcdef"

	Delete(remoteAddr)
	Store(remoteAddr, hash)

	if got := Get(remoteAddr); got != hash {
		t.Fatalf("Get() = %q, want %q", got, hash)
	}

	Delete(remoteAddr)
	if got := Get(remoteAddr); got != "" {
		t.Fatalf("Get() after Delete() = %q, want empty string", got)
	}
}
