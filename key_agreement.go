// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/sha512"
	"io"
	"math/big"
)

type srpKeyAgreement struct {
	N, g  *big.Int
	a, A  *big.Int
	b, B  *big.Int
	v     *big.Int
	pms   []byte
	valid bool // used to fake the authentication process, hiding fact that user doesn't exist
}

func (ka *srpKeyAgreement) generateServerKeyExchange(config *Config, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	if clientHello.srpUser == nil {
		return nil, alert(alertUnknownPskIdentity)
	}

	vbuf, s, grp, err := config.SRPLookup.Lookup(string(clientHello.srpUser))
	if err != nil {
		return nil, err
	}

	// we always calculate a salt & verifier, for the cases where users don't exist.
	// this ensures attackers cannot deduct from error messages if a user exists or not.
	// see http://tools.ietf.org/html/rfc5054#section-2.5.1, at 2.5.1.3 Unknown SRP
	h := hmac.New(sha512.New, []byte(config.SRPSaltKey))
	h.Write([]byte("salt"))
	h.Write(clientHello.srpUser)
	sfake := h.Sum(nil)[:config.SRPSaltSize]

	ka.valid = true
	vfake := SRPVerifier(string(clientHello.srpUser), "password", sfake, grp)
	if vbuf == nil || s == nil {
		vbuf, s = vfake, sfake
		ka.valid = false
	}

	// rfc suggests "at least 256 bits, for 128-bits security"
	bbuf := make([]byte, 512/8)
	_, err = io.ReadFull(config.rand(), bbuf)
	if err != nil {
		return nil, err
	}

	ka.N = grp.N
	ka.g = grp.G
	ka.v = bigint(vbuf)

	ka.b = new(big.Int).SetBytes(bbuf)
	ka.B = srpB(ka.N, ka.g, ka.v, ka.b)

	msg := new(serverKeyExchangeMsg)
	msg.N = ka.N.Bytes()
	msg.g = ka.g.Bytes()
	msg.s = s
	msg.B = ka.B.Bytes()

	return msg, nil
}

func (ka *srpKeyAgreement) processClientKeyExchange(config *Config, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	ka.A = new(big.Int).SetBytes(ckx.A)

	if new(big.Int).Rem(ka.A, ka.N).Sign() == 0 {
		return nil, alert(alertIllegalParameter)
	}

	// always create the fake pms
	fakepms := make([]byte, 16)
	_, err := io.ReadFull(config.rand(), fakepms)
	if err != nil {
		return nil, err
	}

	pms := srpServerPms(ka.N, ka.g, ka.A, ka.B, ka.b, ka.v).Bytes()
	if !ka.valid {
		pms = fakepms
	}
	return pms, nil
}

func (ka *srpKeyAgreement) serverValidExchange() bool {
	return ka.valid
}

func (ka *srpKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, skx *serverKeyExchangeMsg) error {
	ka.N = new(big.Int).SetBytes(skx.N)
	ka.g = new(big.Int).SetBytes(skx.g)
	s := skx.s
	ka.B = new(big.Int).SetBytes(skx.B)

	if new(big.Int).Rem(ka.B, ka.N).Sign() == 0 {
		return alert(alertIllegalParameter)
	}

	if !srpValidGroup(config, ka.N, ka.g) {
		return alert(alertInsufficientSecurity)
	}

	// rfc suggests "at least 256 bits, for 128-bits security"
	abuf := make([]byte, 512/8)
	_, err := io.ReadFull(config.rand(), abuf)
	if err != nil {
		return err
	}
	ka.a = new(big.Int).SetBytes(abuf)

	A, pms := srpClientPms(config.SRPUser, config.SRPPassword, ka.N, ka.g, ka.a, ka.B, s)
	ka.A = A
	ka.pms = pms.Bytes()
	return nil
}

func (ka *srpKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg) ([]byte, *clientKeyExchangeMsg, error) {
	ckx := new(clientKeyExchangeMsg)
	ckx.A = ka.A.Bytes()
	return ka.pms, ckx, nil
}
