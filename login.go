package teamcitylogin

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"io"
	"math/big"
	"strconv"
)

func EncryptPassword(pubKeyHex, password string) string {
	n, _ := new(big.Int).SetString(pubKeyHex, 16)
	e, _ := strconv.ParseInt("10001", 16, 0)
	pubKey := rsa.PublicKey{N: n, E: int(e)}
	data, _ := encryptPKCS1v15(rand.Reader, &pubKey, []byte(password))
	return hex.EncodeToString(data)
}

// copied from rsa/pkcs1v15.go
func encryptPKCS1v15(rand io.Reader, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	k := pub.Size()
	if len(msg) > k-11 {
		return nil, rsa.ErrMessageTooLong
	}

	em := make([]byte, k)
	em[1] = 2

	// TEAMCITY WHAT ARE YOU DOING
	em[len(em)-1] = byte(len(msg))

	ps, mm := em[2:len(em)-len(msg)-2], em[len(em)-len(msg)-1:len(em)-1]
	err := nonZeroRandomBytes(ps, rand)
	if err != nil {
		return nil, err
	}
	em[len(em)-len(msg)-2] = 0
	copy(mm, msg)

	m := new(big.Int).SetBytes(em)

	c := &big.Int{}
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)

	return c.Bytes(), nil
}

// copied from rsa/pkcs1v15.go
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
			// In tests, the PRNG may return all zeros so we do
			// this to break the loop.
			s[i] ^= 0x42
		}
	}

	return
}
