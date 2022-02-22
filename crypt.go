package mysqlpassword

import "crypto/sha256"

// Implement linux crypt function partially:
// https://akkadia.org/drepper/SHA-crypt.txt.
//
// Equal to 'mysql-server/my_crypt_genhash function in mysys/crypt_genhash_impl.cc'.
func cryptSHA256(password, salt []byte, rounds int) []byte {
	h := sha256.New()

	h.Write(password)
	h.Write(salt)
	h.Write(password)
	B := h.Sum(nil)

	h.Reset()
	h.Write(password)
	h.Write(salt)
	for i := 0; i < len(password)/32; i++ {
		h.Write(B)
	}
	h.Write(B[:len(password)%32])
	for i := len(password); i > 0; i >>= 1 {
		if i&1 == 1 {
			h.Write(B)
		} else {
			h.Write(password)
		}
	}
	A := h.Sum(nil)

	h.Reset()
	for i := 0; i < len(password); i++ {
		h.Write(password)
	}
	DP := h.Sum(nil)

	var P []byte
	for i := 0; i < len(password)/32; i++ {
		P = append(P, DP...)
	}
	P = append(P, DP[:len(password)%32]...)

	h.Reset()
	for i := 0; i < 16+int(A[0]); i++ {
		h.Write(salt)
	}
	DS := h.Sum(nil)

	var S []byte
	for i := 0; i < len(salt)/32; i++ {
		S = append(S, DS...)
	}
	S = append(S, DS[:len(salt)%32]...)

	C := A
	for i := 0; i < rounds; i++ {
		h.Reset()
		if i%2 == 1 {
			h.Write(P)
		} else {
			h.Write(C)
		}
		if i%3 != 0 {
			h.Write(S)
		}
		if i%7 != 0 {
			h.Write(P)
		}
		if i%2 == 1 {
			h.Write(C)
		} else {
			h.Write(P)
		}
		C = h.Sum(nil)
	}

	bs := b64From24Bit(C[0], C[10], C[20], 4)
	bs = append(bs, b64From24Bit(C[21], C[1], C[11], 4)...)
	bs = append(bs, b64From24Bit(C[12], C[22], C[2], 4)...)
	bs = append(bs, b64From24Bit(C[3], C[13], C[23], 4)...)
	bs = append(bs, b64From24Bit(C[24], C[4], C[14], 4)...)
	bs = append(bs, b64From24Bit(C[15], C[25], C[5], 4)...)
	bs = append(bs, b64From24Bit(C[6], C[16], C[26], 4)...)
	bs = append(bs, b64From24Bit(C[27], C[7], C[17], 4)...)
	bs = append(bs, b64From24Bit(C[18], C[28], C[8], 4)...)
	bs = append(bs, b64From24Bit(C[9], C[19], C[29], 4)...)
	bs = append(bs, b64From24Bit(0, C[31], C[30], 3)...)

	return bs
}

func b64From24Bit(b2, b1, b0, n uint8) (bs []byte) {
	w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	for n > 0 {
		bs = append(bs, b64t[w&0x3F])
		w >>= 6
		n--
	}
	return bs
}
