package mysql_password

import (
	"bytes"
	"testing"
)

func TestSha256Password_Encrypt(t *testing.T) {
	tables := []struct {
		password string
		salt     string
		expect   string
	}{
		{
			"Unicloud@1221",
			"2&8K[\u0016%\u0018.,vz<c\"WJ*``",
			"$5$2&8K[\u0016%\u0018.,vz<c\"WJ*``$ARuyGf5crLQgb8Hiq0/p.7RVuK1FCQU62RoIx.HRPV9",
		},
		{
			"Unicloud@1221",
			"r|{\u00046\u0005T3MBb\a(g'O`\f.1",
			"$5$r|{\u00046\u0005T3MBb\a(g'O`\f.1$r1RtpWg7e5frHkx8U2oj65lPcdQzi5HDEGeVjpopc6/",
		},
	}

	h := NewSHA256()
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

func TestSha256Password_Validate(t *testing.T) {
	tables := []struct {
		password string
		authStr  string
	}{
		{"Unicloud@1221",
			"$5$2&8K[\u0016%\u0018.,vz<c\"WJ*``$ARuyGf5crLQgb8Hiq0/p.7RVuK1FCQU62RoIx.HRPV9",
		},
		{
			"Unicloud@1221",
			"$5$r|{\u00046\u0005T3MBb\a(g'O`\f.1$r1RtpWg7e5frHkx8U2oj65lPcdQzi5HDEGeVjpopc6/",
		},
	}

	h := NewSHA256()
	for _, table := range tables {
		if err := h.Validate([]byte(table.authStr), []byte(table.password)); err != nil {
			t.Fatalf("h.Validate(): %v\n", err)
		}
	}
}
