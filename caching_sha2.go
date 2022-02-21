package mysql_password

import (
	"bytes"
	"errors"
	"strconv"
)

var (
	ErrInvalidSalt                 = errors.New("invalid salt")
	ErrInvalidAuthenticationString = errors.New("invalid authentication_string")
	ErrMismatch                    = errors.New("key mismatches digest")
)

const (
	RoundsMax     = 4095000
	RoundsMin     = 5000
	RoundsDefault = 5000

	b64t = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

type cachingSHA2 struct{}

func NewCachingSHA2() Cipher {
	return &cachingSHA2{}
}

func (c *cachingSHA2) Validate(as, password []byte) error {
	if len(as) != 70 {
		return ErrInvalidAuthenticationString
	}

	b, err := c.Encrypt(password, as[:27])
	if err != nil {
		return err
	}

	if bytes.Equal(b, as) {
		return nil
	}
	return ErrMismatch
}

// Encrypt return value would be in format:
// $A$<3 byte rounds_hex>$<20 byte salt><43 byte sha256_digest_base64>
//
// Salt format: $A$<3 byte rounds_hex>$<20 byte salt>
func (c *cachingSHA2) Encrypt(password []byte, salt []byte) ([]byte, error) {
	saltLen := 3 + 3 + 1 + 20
	if len(salt) != saltLen {
		return nil, ErrInvalidSalt
	}

	if ok := bytes.HasPrefix(salt, []byte("$A$")); !ok {
		return nil, ErrInvalidSalt
	}

	roundsFactor, err := strconv.ParseInt(string(salt[3:6]), 16, 0)
	if err != nil {
		return nil, err
	}
	rounds := roundsFactor * 1000
	if rounds < RoundsMin || rounds > RoundsMax {
		rounds = RoundsDefault
	}

	digest := cryptSHA256(password, salt[7:], int(rounds))

	as := make([]byte, saltLen+43)
	copy(as, salt)
	copy(as[saltLen:], digest)

	return as, nil
}
