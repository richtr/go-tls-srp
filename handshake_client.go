// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/subtle"
	"errors"
	"io"
)

func (c *Conn) clientHandshake() error {
	hello := &clientHelloMsg{
		vers:               c.config.maxVersion(),
		compressionMethods: []uint8{compressionNone},
		random:             make([]byte, 32),
		serverName:         c.config.ServerName,
		srpUser:            []byte(c.config.SRPUser),
	}

	possibleCipherSuites := c.config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range cipherSuites {
			if suite.id != suiteId {
				continue
			}
			// Don't advertise TLS 1.2-only cipher suites unless
			// we're attempting TLS 1.2.
			if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	t := uint32(c.config.time().Unix())
	hello.random[0] = byte(t >> 24)
	hello.random[1] = byte(t >> 16)
	hello.random[2] = byte(t >> 8)
	hello.random[3] = byte(t)
	_, err := io.ReadFull(c.config.rand(), hello.random[4:])
	if err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("short read from Rand")
	}

	c.writeRecord(recordTypeHandshake, hello.marshal())

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		return c.sendAlert(alertUnexpectedMessage)
	}

	vers, ok := c.config.mutualVersion(serverHello.vers)
	if !ok || vers < VersionTLS10 {
		// TLS 1.0 is the minimum version supported as a client.
		return c.sendAlert(alertProtocolVersion)
	}
	c.vers = vers
	c.haveVers = true

	finishedHash := newFinishedHash(c.vers)
	finishedHash.Write(hello.marshal())
	finishedHash.Write(serverHello.marshal())

	if serverHello.compressionMethod != compressionNone {
		return c.sendAlert(alertUnexpectedMessage)
	}

	suite := mutualCipherSuite(c.config.cipherSuites(), serverHello.cipherSuite)
	if suite == nil {
		return c.sendAlert(alertHandshakeFailure)
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	keyAgreement := suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if !ok {
		return c.sendAlert(alertUnexpectedMessage)
	}

	finishedHash.Write(skx.marshal())
	err = keyAgreement.processServerKeyExchange(c.config, hello, serverHello, skx)
	if err != nil {
		switch e := err.(type) {
		case alert:
			c.sendAlert(e)
		default:
			c.sendAlert(alertUnexpectedMessage)
		}
		return err
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		return c.sendAlert(alertUnexpectedMessage)
	}
	finishedHash.Write(shd.marshal())

	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hello)
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if ckx != nil {
		finishedHash.Write(ckx.marshal())
		c.writeRecord(recordTypeHandshake, ckx.marshal())
	}

	masterSecret := masterFromPreMasterSecret(c.vers, preMasterSecret, hello.random, serverHello.random)
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, masterSecret, hello.random, serverHello.random, suite.macLen, suite.keyLen, suite.ivLen)

	var clientCipher interface{}
	var clientHash macFunction
	clientCipher = suite.cipher(clientKey, clientIV, false /* not for reading */)
	clientHash = suite.mac(c.vers, clientMAC)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.writeRecord(recordTypeChangeCipherSpec, []byte{1})

	finished := new(finishedMsg)
	finished.verifyData = finishedHash.clientSum(masterSecret)
	finishedHash.Write(finished.marshal())
	c.writeRecord(recordTypeHandshake, finished.marshal())

	var serverCipher interface{}
	var serverHash macFunction
	serverCipher = suite.cipher(serverKey, serverIV, true /* for reading */)
	serverHash = suite.mac(c.vers, serverMAC)
	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.readRecord(recordTypeChangeCipherSpec)
	if err := c.error(); err != nil {
		return err
	}

	msg, err = c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		return c.sendAlert(alertUnexpectedMessage)
	}

	verify := finishedHash.serverSum(masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		return c.sendAlert(alertHandshakeFailure)
	}

	c.handshakeComplete = true
	c.cipherSuite = suite.id
	return nil
}

// mutualProtocol finds the mutual Next Protocol Negotiation protocol given the
// set of client and server supported protocols. The set of client supported
// protocols must not be empty. It returns the resulting protocol and flag
// indicating if the fallback case was reached.
func mutualProtocol(clientProtos, serverProtos []string) (string, bool) {
	for _, s := range serverProtos {
		for _, c := range clientProtos {
			if s == c {
				return s, false
			}
		}
	}

	return clientProtos[0], true
}
