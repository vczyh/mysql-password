package mysqlpassword

import (
	"bytes"
	"testing"
)

func TestCachingSHA2_Encrypt(t *testing.T) {
	tables := []struct {
		password string
		salt     string
		expect   string
	}{
		{"Unicloud@1221", "$A$005$2r\u0010\u0003C&s:2gn\u0001\u0001A{J\a\u0006h!",
			"$A$005$2r\u0010\u0003C&s:2gn\u0001\u0001A{J\a\u0006h!eqK8wNxJuiftm.mJfcKsw5qJxPKtC178tc2JBEq.xL7",
		},
	}

	h := NewCachingSHA2()
	for _, table := range tables {
		as, err := h.Encrypt([]byte(table.password), []byte(table.salt))
		if err != nil {
			t.Fatalf("h.Encrypt(): %v\n", err)
		}
		if !bytes.Equal(as, []byte(table.expect)) {
			t.Fatalf("%v", table)
		}
	}
}

func TestCachingSHA2_Validate(t *testing.T) {
	tables := []struct {
		password string
		authStr  string
	}{
		{"Unicloud@1221",
			"$A$005$2r\u0010\u0003C&s:2gn\u0001\u0001A{J\a\u0006h!eqK8wNxJuiftm.mJfcKsw5qJxPKtC178tc2JBEq.xL7",
		},
	}

	h := NewCachingSHA2()
	for _, table := range tables {
		if err := h.Validate([]byte(table.authStr), []byte(table.password)); err != nil {
			t.Fatalf("h.Validate(): %v\n", err)
		}
	}
}
