package mysqlpassword

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

type mysqlNative struct{}

func NewMySQLNative() Cipher {
	return &mysqlNative{}
}

func (m *mysqlNative) Validate(as, password []byte) error {
	b, err := m.Encrypt(password, nil)
	if err != nil {
		return err
	}

	if bytes.Equal(b, as) {
		return nil
	}
	return ErrMismatch
}

// Encrypt return SHA1(SHA1(password)).
// Salt would be ignored, because mysql_native_password digest don't need salt.
func (m *mysqlNative) Encrypt(password []byte, salt []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(password)
	stage1 := h.Sum(nil)

	h.Reset()
	h.Write(stage1)
	stage2 := h.Sum(nil)

	hexStr := hex.EncodeToString(stage2)

	as := make([]byte, 1+len(hexStr)) // 41
	copy(as, []byte{'*'})
	copy(as[1:], strings.ToUpper(hexStr))

	return as, nil
}
