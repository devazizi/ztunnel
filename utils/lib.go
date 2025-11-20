package utils

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const NonceSize = 12

// Encrypt payload with ChaCha20-Poly1305
func Encrypt(aead cipher.AEAD, seq uint64, payload []byte) ([]byte, []byte, error) {
	nonce := make([]byte, NonceSize)
	_, _ = rand.Read(nonce)

	// Include sequence number in AD
	ad := make([]byte, 8)
	binary.BigEndian.PutUint64(ad, seq)
	ct := aead.Seal(nil, nonce, payload, ad)
	return nonce, ct, nil
}

// Decrypt payload with AEAD
func Decrypt(aead cipher.AEAD, seq uint64, nonce, ct []byte) ([]byte, error) {
	ad := make([]byte, 8)
	binary.BigEndian.PutUint64(ad, seq)
	return aead.Open(nil, nonce, ct, ad)
}

// Read full message from io.Reader
func ReadFullMsg(r io.Reader) ([]byte, []byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf)
	if length < NonceSize {
		return nil, nil, fmt.Errorf("invalid packet length")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, nil, err
	}
	return data[:NonceSize], data[NonceSize:], nil
}

// Write full message
func WriteFullMsg(w io.Writer, nonce, payload []byte) error {
	total := uint32(len(nonce) + len(payload))
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, total)
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}
