package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	_ "github.com/lib/pq"
)

type Encryption struct {
	SECRET_KEY string
	Bytes      []byte
}

func NewEncryption() *Encryption {
	return &Encryption{
		SECRET_KEY: "Key137&*#!~c(8~=2?.?%b74",
		Bytes:      []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05},
	}
}

func (e *Encryption) Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func (e *Encryption) Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func (e *Encryption) Encrypt(text string) (string, error) {
	block, err := aes.NewCipher([]byte(e.SECRET_KEY))

	if err != nil {
		return "", err
	}

	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, e.Bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)

	return e.Encode(cipherText), nil
}

// Decrypt method is to extract back the encrypted text
func (e *Encryption) Decrypt(text string) (string, error) {
	block, err := aes.NewCipher([]byte(e.SECRET_KEY))

	if err != nil {
		return "", err
	}

	cipherText := e.Decode(text)
	cfb := cipher.NewCFBDecrypter(block, e.Bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)

	return string(plainText), nil
}
