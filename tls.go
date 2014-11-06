// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/sha512"
	"errors"
	"net"
	"strings"
)

func testServerConfig(config *Config) error {
	if config == nil {
		return errors.New("nil config")
	}
	if config.SRPLookup == nil || config.SRPSaltKey == "" || config.SRPSaltSize <= 0 || config.SRPSaltSize > sha512.Size {
		return errors.New("must set SRPLookup, SRPSaltKey and SRPSaltSize in config")
	}
	return nil
}

func testClientConfig(config *Config) error {
	if config == nil {
		return errors.New("nil config")
	}
	if config.SRPUser == "" {
		return errors.New("must set config.SRPUser")
	}
	return nil
}

// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must have
// SRPLookup, SRPSaltKey and SRPSaltSize set.
func Server(conn net.Conn, config *Config) *Conn {
	err := testServerConfig(config)
	if err != nil {
		panic(err)
	}
	return &Conn{conn: conn, config: config}
}

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and should have SRPUser and SRPPassword set.
func Client(conn net.Conn, config *Config) *Conn {
	err := testClientConfig(config)
	if err != nil {
		panic(err)
	}
	return &Conn{conn: conn, config: config, isClient: true}
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *Config
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection c is a *tls.Conn.
func (l *listener) Accept() (c net.Conn, err error) {
	c, err = l.Listener.Accept()
	if err != nil {
		return
	}
	return Server(c, l.config), nil
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with Server.
// The configuration config must be non-nil and must have
// SRPLookup, SRPSaltKey and SRPSaltSize set.
func NewListener(inner net.Listener, config *Config) net.Listener {
	err := testServerConfig(config)
	if err != nil {
		panic(err)
	}
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must have
// SRPLookup, SRPSaltKey and SRPSaltSize set.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	err := testServerConfig(config)
	if err != nil {
		return nil, errors.New("tls.Listen: " + err.Error())
	}

	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
// Configuration config must be non-nil and should have SRPUser and
// SRPPassword set.
func Dial(network, addr string, config *Config) (*Conn, error) {
	err := testClientConfig(config)
	if err != nil {
		return nil, errors.New("tls.Dial: " + err.Error())
	}

	raddr := addr
	c, err := net.Dial(network, raddr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(raddr, ":")
	if colonPos == -1 {
		colonPos = len(raddr)
	}
	hostname := raddr[:colonPos]

	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := *config
		c.ServerName = hostname
		config = &c
	}

	conn := Client(c, config)
	if err = conn.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	return conn, nil
}
