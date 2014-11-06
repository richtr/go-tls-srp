// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/subtle"
	"io"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c            *Conn
	clientHello  *clientHelloMsg
	hello        *serverHelloMsg
	suite        *cipherSuite
	sessionState *sessionState
	finishedHash finishedHash
	masterSecret []byte
	srpUser      []byte
	srpValid     bool
}

// serverHandshake performs a TLS handshake as a server.
func (c *Conn) serverHandshake() error {
	config := c.config

	// If this is the first server handshake, we generate a random key to
	// encrypt the tickets with.
	config.serverInitOnce.Do(config.serverInit)

	hs := serverHandshakeState{
		c: c,
	}
	isResume, err := hs.readClientHello()
	if err != nil {
		return err
	}

	// For an overview of TLS handshaking, see https://tools.ietf.org/html/rfc5246#section-7.3
	if isResume {
		// The client has included a session ticket and so we do an abbreviated handshake.
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
		c.didResume = true
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readFinished(); err != nil {
			return err
		}
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(); err != nil {
			return err
		}
	}
	c.srpUser = string(hs.srpUser)
	c.handshakeComplete = true

	return nil
}

// readClientHello reads a ClientHello message from the client and decides
// whether we will perform session resumption.
func (hs *serverHandshakeState) readClientHello() (isResume bool, err error) {
	config := hs.c.config
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return false, err
	}
	var ok bool
	hs.clientHello, ok = msg.(*clientHelloMsg)
	if !ok {
		return false, c.sendAlert(alertUnexpectedMessage)
	}
	c.vers, ok = config.mutualVersion(hs.clientHello.vers)
	if !ok {
		return false, c.sendAlert(alertProtocolVersion)
	}
	c.haveVers = true

	hs.finishedHash = newFinishedHash(c.vers)
	hs.finishedHash.Write(hs.clientHello.marshal())

	hs.hello = new(serverHelloMsg)

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		return false, c.sendAlert(alertHandshakeFailure)
	}

	hs.hello.vers = c.vers
	t := uint32(config.time().Unix())
	hs.hello.random = make([]byte, 32)
	hs.hello.random[0] = byte(t >> 24)
	hs.hello.random[1] = byte(t >> 16)
	hs.hello.random[2] = byte(t >> 8)
	hs.hello.random[3] = byte(t)
	_, err = io.ReadFull(config.rand(), hs.hello.random[4:])
	if err != nil {
		return false, c.sendAlert(alertInternalError)
	}
	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	if hs.checkForResumption() {
		return true, nil
	}

	var preferenceList, supportedList []uint16
	if c.config.PreferServerCipherSuites {
		preferenceList = c.config.cipherSuites()
		supportedList = hs.clientHello.cipherSuites
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = c.config.cipherSuites()
	}

	for _, id := range preferenceList {
		if hs.suite = c.tryCipherSuite(id, supportedList, c.vers, false, false); hs.suite != nil {
			break
		}
	}

	if hs.suite == nil {
		return false, c.sendAlert(alertHandshakeFailure)
	}

	return false, nil
}

// checkForResumption returns true if we should perform resumption on this connection.
func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c

	var ok bool
	if hs.sessionState, ok = c.decryptTicket(hs.clientHello.sessionTicket); !ok {
		return false
	}

	if hs.sessionState.vers > hs.clientHello.vers {
		return false
	}
	if vers, ok := c.config.mutualVersion(hs.sessionState.vers); !ok || vers != hs.sessionState.vers {
		return false
	}

	cipherSuiteOk := false
	// Check that the client is still offering the ciphersuite in the session.
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}

	// Check that we also support the ciphersuite from the session.
	hs.suite = c.tryCipherSuite(hs.sessionState.cipherSuite, c.config.cipherSuites(), hs.sessionState.vers, false, false)
	if hs.suite == nil {
		return false
	}

	// Check that client wants the same username.
	if !bytes.Equal(hs.clientHello.srpUser, []byte(hs.sessionState.srpUser)) {
		return false
	}

	// Verify that user is still valid.
	v, _, _, err := hs.c.config.SRPLookup.Lookup(string(hs.clientHello.srpUser))
	if v == nil || err != nil {
		return false
	}

	return true
}

func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.finishedHash.Write(hs.hello.marshal())
	c.writeRecord(recordTypeHandshake, hs.hello.marshal())

	hs.masterSecret = hs.sessionState.masterSecret

	hs.srpUser = hs.sessionState.srpUser
	hs.srpValid = true

	return nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	config := hs.c.config
	c := hs.c

	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id
	hs.finishedHash.Write(hs.hello.marshal())
	c.writeRecord(recordTypeHandshake, hs.hello.marshal())

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(config, hs.clientHello, hs.hello)
	if err != nil {
		switch e := err.(type) {
		case alert:
			c.sendAlert(e)
		default:
			c.sendAlert(alertHandshakeFailure)
		}
		return err
	}
	hs.srpValid = keyAgreement.serverValidExchange()
	hs.finishedHash.Write(skx.marshal())
	c.writeRecord(recordTypeHandshake, skx.marshal())

	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())
	c.writeRecord(recordTypeHandshake, helloDone.marshal())

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		return c.sendAlert(alertUnexpectedMessage)
	}
	hs.finishedHash.Write(ckx.marshal())

	preMasterSecret, err := keyAgreement.processClientKeyExchange(config, ckx, c.vers)
	if err != nil {
		switch e := err.(type) {
		case alert:
			c.sendAlert(e)
		default:
			c.sendAlert(alertHandshakeFailure)
		}
		return err
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, preMasterSecret, hs.clientHello.random, hs.hello.random)
	hs.srpUser = hs.clientHello.srpUser

	return nil
}

func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction

	clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
	clientHash = hs.suite.mac(c.vers, clientMAC)
	serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
	serverHash = hs.suite.mac(c.vers, serverMAC)

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished() error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if err := c.error(); err != nil {
		return err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		return c.sendAlert(alertUnexpectedMessage)
	}

	if !hs.srpValid {
		// we should not be able to get here.
		// the user didn't exist and we generated a fake pms (and master secret).
		// the readHandshake() above should have resulted in alertBadRecordMac
		return c.sendAlert(alertBadRecordMAC)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		return c.sendAlert(alertHandshakeFailure)
	}

	hs.finishedHash.Write(clientFinished.marshal())

	return nil
}

func (hs *serverHandshakeState) sendSessionTicket() error {
	if !hs.hello.ticketSupported {
		return nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	var err error
	state := sessionState{
		vers:         c.vers,
		cipherSuite:  hs.suite.id,
		masterSecret: hs.masterSecret,
		srpUser:      hs.srpUser,
	}
	m.ticket, err = c.encryptTicket(&state)
	if err != nil {
		return err
	}

	hs.finishedHash.Write(m.marshal())
	c.writeRecord(recordTypeHandshake, m.marshal())

	return nil
}

func (hs *serverHandshakeState) sendFinished() error {
	c := hs.c

	c.writeRecord(recordTypeChangeCipherSpec, []byte{1})

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	c.writeRecord(recordTypeHandshake, finished.marshal())

	c.cipherSuite = hs.suite.id

	return nil
}

// tryCipherSuite returns a cipherSuite with the given id if that cipher suite
// is acceptable to use.
func (c *Conn) tryCipherSuite(id uint16, supportedCipherSuites []uint16, version uint16, ellipticOk, ecdsaOk bool) *cipherSuite {
	for _, supported := range supportedCipherSuites {
		if id == supported {
			var candidate *cipherSuite

			for _, s := range cipherSuites {
				if s.id == id {
					candidate = s
					break
				}
			}
			if candidate == nil {
				continue
			}
			// Don't select a ciphersuite which we can't
			// support for this client.
			if (candidate.flags&suiteECDHE != 0) && !ellipticOk {
				continue
			}
			if (candidate.flags&suiteECDSA != 0) != ecdsaOk {
				continue
			}
			if version < VersionTLS12 && candidate.flags&suiteTLS12 != 0 {
				continue
			}
			return candidate
		}
	}

	return nil
}
