package mysql_password

import (
	"bytes"
)

type sha256Password struct{}

func NewSHA256() Cipher {
	return &sha256Password{}
}

func (c *sha256Password) Validate(as, password []byte) error {
	if len(as) != 67 {
		return ErrInvalidAuthenticationString
	}

	b, err := c.Encrypt(password, as[3:23])
	if err != nil {
		return err
	}

	if bytes.Equal(b, as) {
		return nil
	}
	return ErrMismatch
}

// Encrypt return value would be in format:
// $5$<20 byte salt>$<43 byte sha256_digest_base64>
//
// Salt only contains 20 random bytes.
func (c *sha256Password) Encrypt(password []byte, salt []byte) ([]byte, error) {
	digest := cryptSHA256(password, salt, 5000)

	as := make([]byte, 3+20+1+43)
	copy(as, "$5$")
	copy(as[3:], salt)
	copy(as[3+20:], "$")
	copy(as[3+20+1:], digest)

	return as, nil
}
