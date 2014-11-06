// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"io"
	"sync"
	"time"
)

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)

const (
	maxPlaintext    = 16384        // maximum plaintext payload length
	maxCiphertext   = 16384 + 2048 // maximum ciphertext payload length
	recordHeaderLen = 5            // record header length
	maxHandshake    = 65536        // maximum handshake we support (protocol max is 16 MB)

	minVersion = VersionSSL30
	maxVersion = VersionTLS12
)

// TLS record types.
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// TLS handshake message types.
const (
	typeClientHello       uint8 = 1
	typeServerHello       uint8 = 2
	typeNewSessionTicket  uint8 = 4
	typeServerKeyExchange uint8 = 12
	typeServerHelloDone   uint8 = 14
	typeClientKeyExchange uint8 = 16
	typeFinished          uint8 = 20
)

// TLS compression types.
const (
	compressionNone uint8 = 0
)

// TLS extension numbers
var (
	extensionServerName    uint16 = 0
	extensionSRP           uint16 = 12
	extensionSessionTicket uint16 = 35
)

// Hash functions for TLS 1.2 (See RFC 5246, section A.4.1)
const (
	hashSHA1   uint8 = 2
	hashSHA256 uint8 = 4
)

// ConnectionState records basic TLS details about the connection.
type ConnectionState struct {
	HandshakeComplete bool   // TLS handshake is complete
	CipherSuite       uint16 // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	ServerName        string // server name requested by client, if any (server side only)
	SRPUser           string // authenticated SRP user
}

// Lookuper is an interface for looking up SRP account information.
type Lookuper interface {
	// Lookup looks up the user and returns the verifier (v),
	// and salt (s) and group (grp) used to create the verifier.
	// If the user is absent, Lookup should return a nil v and
	// nil s but a valid grp. In this case, grp is used to generate a
	// verifier, in order to make it harder for attackers to enumerate
	// valid accounts.
	Lookup(user string) (v, s []byte, grp SRPGroup, err error)
}

// A Config structure is used to configure a TLS client or server. After one
// has been passed to a TLS function it must not be modified.
type Config struct {
	// Rand provides the source of entropy for nonces and RSA blinding.
	// If Rand is nil, TLS uses the cryptographic random reader in package
	// crypto/rand.
	Rand io.Reader

	// Time returns the current time as the number of seconds since the epoch.
	// If Time is nil, TLS uses time.Now.
	Time func() time.Time

	// ServerName is included in the client's handshake to support virtual
	// hosting.
	ServerName string

	// CipherSuites is a list of supported cipher suites. If CipherSuites
	// is nil, TLS uses a list of suites supported by the implementation.
	CipherSuites []uint16

	// PreferServerCipherSuites controls whether the server selects the
	// client's most preferred ciphersuite, or the server's most preferred
	// ciphersuite. If true then the server's preference, as expressed in
	// the order of elements in CipherSuites, is used.
	PreferServerCipherSuites bool

	// SessionTicketsDisabled may be set to true to disable session ticket
	// (resumption) support.
	SessionTicketsDisabled bool

	// SessionTicketKey is used by TLS servers to provide session
	// resumption. See RFC 5077. If zero, it will be filled with
	// random data before the first server handshake.
	//
	// If multiple servers are terminating connections for the same host
	// they should all have the same SessionTicketKey. If the
	// SessionTicketKey leaks, previously recorded and future TLS
	// connections using that key are compromised.
	SessionTicketKey [32]byte

	// MinVersion contains the minimum SSL/TLS version that is acceptable.
	// If zero, then SSLv3 is taken as the minimum.
	MinVersion uint16

	// MaxVersion contains the maximum SSL/TLS version that is acceptable.
	// If zero, then the maximum version supported by this package is used,
	// which is currently TLS 1.2.
	MaxVersion uint16

	serverInitOnce sync.Once // guards calling (*Config).serverInit

	// For SRP servers:
	SRPLookup   Lookuper // for looking up salt, verifier & srp group for a username
	SRPSaltKey  string   // used in hmac for generating fake salts, for hiding existence of account
	SRPSaltSize int      // size of fake salts (<= 64), should match what is used for valid accounts

	// For SRP clients:
	SRPUser     string
	SRPPassword string
	SRPGroups   []*SRPGroup // Groups allowed from server.  If nil, all groups from RFC 5054 are allowed.
}

func (c *Config) serverInit() {
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) time() time.Time {
	t := c.Time
	if t == nil {
		t = time.Now
	}
	return t()
}

func (c *Config) cipherSuites() []uint16 {
	s := c.CipherSuites
	if s == nil {
		s = defaultCipherSuites()
	}
	return s
}

func (c *Config) minVersion() uint16 {
	if c == nil || c.MinVersion == 0 {
		return minVersion
	}
	return c.MinVersion
}

func (c *Config) maxVersion() uint16 {
	if c == nil || c.MaxVersion == 0 {
		return maxVersion
	}
	return c.MaxVersion
}

// mutualVersion returns the protocol version to use given the advertised
// version of the peer.
func (c *Config) mutualVersion(vers uint16) (uint16, bool) {
	minVersion := c.minVersion()
	maxVersion := c.maxVersion()

	if vers < minVersion {
		return 0, false
	}
	if vers > maxVersion {
		vers = maxVersion
	}
	return vers, true
}

// A TLS record.
type record struct {
	contentType  recordType
	major, minor uint8
	payload      []byte
}

type handshakeMessage interface {
	marshal() []byte
	unmarshal([]byte) bool
}

var (
	once                   sync.Once
	varDefaultCipherSuites []uint16
)

func defaultCipherSuites() []uint16 {
	once.Do(initDefaultCipherSuites)
	return varDefaultCipherSuites
}

func initDefaultCipherSuites() {
	varDefaultCipherSuites = make([]uint16, len(cipherSuites))
	for i, suite := range cipherSuites {
		varDefaultCipherSuites[i] = suite.id
	}
}
