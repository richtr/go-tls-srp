// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

// sessionState contains the information that is serialized into a session
// ticket in order to later resume a connection.
type sessionState struct {
	vers         uint16
	cipherSuite  uint16
	masterSecret []byte
	srpUser      []byte
}

func (s *sessionState) equal(i interface{}) bool {
	s1, ok := i.(*sessionState)
	if !ok {
		return false
	}

	if s.vers != s1.vers ||
		s.cipherSuite != s1.cipherSuite ||
		!bytes.Equal(s.masterSecret, s1.masterSecret) {
		return false
	}

	if !bytes.Equal(s.srpUser, s1.srpUser) {
		return false
	}

	return true
}

func (s *sessionState) marshal() []byte {
	length := 2 + 2 + 2 + len(s.masterSecret) + 1 + len(s.srpUser)

	ret := make([]byte, length)
	x := ret
	x[0] = byte(s.vers >> 8)
	x[1] = byte(s.vers)
	x[2] = byte(s.cipherSuite >> 8)
	x[3] = byte(s.cipherSuite)
	x[4] = byte(len(s.masterSecret) >> 8)
	x[5] = byte(len(s.masterSecret))
	x = x[6:]
	copy(x, s.masterSecret)
	x = x[len(s.masterSecret):]

	x[0] = byte(len(s.srpUser))
	copy(x[1:], s.srpUser)

	return ret
}

func (s *sessionState) unmarshal(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	s.vers = uint16(data[0])<<8 | uint16(data[1])
	s.cipherSuite = uint16(data[2])<<8 | uint16(data[3])
	masterSecretLen := int(data[4])<<8 | int(data[5])
	data = data[6:]
	if len(data) < masterSecretLen {
		return false
	}

	s.masterSecret = data[:masterSecretLen]
	data = data[masterSecretLen:]

	if len(data) < 1 {
		return false
	}
	length := int(data[0])
	if len(data) != 1+length {
		return false
	}
	s.srpUser = data[1:]

	return true
}

func (c *Conn) encryptTicket(state *sessionState) ([]byte, error) {
	serialized := state.marshal()
	encrypted := make([]byte, aes.BlockSize+len(serialized)+sha256.Size)
	iv := encrypted[:aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	if _, err := io.ReadFull(c.config.rand(), iv); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.config.SessionTicketKey[:16])
	if err != nil {
		return nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	cipher.NewCTR(block, iv).XORKeyStream(encrypted[aes.BlockSize:], serialized)

	mac := hmac.New(sha256.New, c.config.SessionTicketKey[16:32])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	mac.Sum(macBytes[:0])

	return encrypted, nil
}

func (c *Conn) decryptTicket(encrypted []byte) (*sessionState, bool) {
	if len(encrypted) < aes.BlockSize+sha256.Size {
		return nil, false
	}

	iv := encrypted[:aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	mac := hmac.New(sha256.New, c.config.SessionTicketKey[16:32])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(macBytes, expected) != 1 {
		return nil, false
	}

	block, err := aes.NewCipher(c.config.SessionTicketKey[:16])
	if err != nil {
		return nil, false
	}
	ciphertext := encrypted[aes.BlockSize : len(encrypted)-sha256.Size]
	plaintext := ciphertext
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)

	state := new(sessionState)
	ok := state.unmarshal(plaintext)
	return state, ok
}
