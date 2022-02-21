package mysql_password

import (
	"bytes"
	"testing"
)

func TestMysqlNative_Encrypt(t *testing.T) {
	tables := []struct {
		password string
		expect   string
	}{
		{"Unicloud@1221", "*00F3FD10537EE7810FA9CADB528C47B5460FA98A"},
	}

	h := NewMySQLNative()
	for _, table := range tables {
		as, err := h.Encrypt([]byte(table.password), nil)
		if err != nil {
			t.Fatalf("h.Encrypt(): %v\n", err)
		}
		if !bytes.Equal(as, []byte(table.expect)) {
			t.Fatalf("%v", table)
		}
	}
}

func TestMysqlNative_Validate(t *testing.T) {
	tables := []struct {
		password string
		authStr  string
	}{
		{"Unicloud@1221", "*00F3FD10537EE7810FA9CADB528C47B5460FA98A"},
	}

	h := NewMySQLNative()
	for _, table := range tables {
		if err := h.Validate([]byte(table.authStr), []byte(table.password)); err != nil {
			t.Fatalf("h.Validate(): %v\n", err)
		}
	}
}
