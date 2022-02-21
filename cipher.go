package mysql_password

type Cipher interface {
	// Validate compares authentication_string of mysql.user table
	// with possible password equivalent.
	//
	// return nil if match, err == ErrMismatch if mismatch.
	Validate(as, password []byte) error

	// Encrypt performs the hash, return result is equivalent to the
	// authentication_string of mysql.user table.
	Encrypt(password []byte, salt []byte) ([]byte, error)
}
