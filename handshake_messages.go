// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "bytes"

type clientHelloMsg struct {
	raw                []byte
	vers               uint16
	random             []byte
	sessionId          []byte
	cipherSuites       []uint16
	compressionMethods []uint8
	serverName         string
	ticketSupported    bool
	sessionTicket      []uint8
	srpUser            []byte
}

func (m *clientHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		eqUint16s(m.cipherSuites, m1.cipherSuites) &&
		bytes.Equal(m.compressionMethods, m1.compressionMethods) &&
		m.serverName == m1.serverName &&
		m.ticketSupported == m1.ticketSupported &&
		bytes.Equal(m.sessionTicket, m1.sessionTicket) &&
		bytes.Equal(m.srpUser, m1.srpUser)
}

func (m *clientHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + 32 + 1 + len(m.sessionId) + 2 + len(m.cipherSuites)*2 + 1 + len(m.compressionMethods)
	numExtensions := 0
	extensionsLength := 0
	if len(m.serverName) > 0 {
		extensionsLength += 5 + len(m.serverName)
		numExtensions++
	}
	if m.ticketSupported {
		extensionsLength += len(m.sessionTicket)
		numExtensions++
	}
	if m.srpUser != nil {
		extensionsLength += 1 + len(m.srpUser)
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	y := x[39+len(m.sessionId):]
	y[0] = uint8(len(m.cipherSuites) >> 7)
	y[1] = uint8(len(m.cipherSuites) << 1)
	for i, suite := range m.cipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.cipherSuites)*2:]
	z[0] = uint8(len(m.compressionMethods))
	copy(z[1:], m.compressionMethods)

	z = z[1+len(m.compressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if len(m.serverName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName)
		l := len(m.serverName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		z[0] = byte((len(m.serverName) + 3) >> 8)
		z[1] = byte(len(m.serverName) + 3)
		z[3] = byte(len(m.serverName) >> 8)
		z[4] = byte(len(m.serverName))
		copy(z[5:], []byte(m.serverName))
		z = z[l:]
	}
	if m.ticketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.sessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.sessionTicket)
		z = z[len(m.sessionTicket):]
	}
	if m.srpUser != nil {
		// http://tools.ietf.org/html/rfc5054#section-2.8
		z[0] = byte(extensionSRP >> 8)
		z[1] = byte(extensionSRP)
		srpI := m.srpUser
		l := len(srpI) + 1
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z[4] = byte(len(srpI))
		z = z[5:]
		copy(z, srpI)
		z = z[len(srpI):]
	}

	m.raw = x

	return x
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.cipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.serverName = ""
	m.ticketSupported = false
	m.sessionTicket = nil

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionServerName:
			if length < 2 {
				return false
			}
			numNames := int(data[0])<<8 | int(data[1])
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.serverName = string(d[0:nameLen])
					break
				}
				d = d[nameLen:]
			}
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.ticketSupported = true
			m.sessionTicket = data[:length]
		case extensionSRP:
			// http://tools.ietf.org/html/rfc5054#section-2.8
			if length < 1 {
				return false
			}
			l := int(data[0])
			if length != l+1 {
				return false
			}
			m.srpUser = make([]byte, l)
			copy(m.srpUser, data[1:length])
		}
		data = data[length:]
	}

	return true
}

type serverHelloMsg struct {
	raw               []byte
	vers              uint16
	random            []byte
	sessionId         []byte
	cipherSuite       uint16
	compressionMethod uint8
	ticketSupported   bool
}

func (m *serverHelloMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverHelloMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		m.vers == m1.vers &&
		bytes.Equal(m.random, m1.random) &&
		bytes.Equal(m.sessionId, m1.sessionId) &&
		m.cipherSuite == m1.cipherSuite &&
		m.compressionMethod == m1.compressionMethod &&
		m.ticketSupported == m1.ticketSupported
}

func (m *serverHelloMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 38 + len(m.sessionId)
	numExtensions := 0
	extensionsLength := 0

	if m.ticketSupported {
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeServerHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.vers >> 8)
	x[5] = uint8(m.vers)
	copy(x[6:38], m.random)
	x[38] = uint8(len(m.sessionId))
	copy(x[39:39+len(m.sessionId)], m.sessionId)
	z := x[39+len(m.sessionId):]
	z[0] = uint8(m.cipherSuite >> 8)
	z[1] = uint8(m.cipherSuite)
	z[2] = uint8(m.compressionMethod)

	z = z[3:]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.ticketSupported {
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		z = z[4:]
	}

	m.raw = x

	return x
}

func (m *serverHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.sessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 3 {
		return false
	}
	m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
	m.compressionMethod = data[2]
	data = data[3:]

	m.ticketSupported = false

	if len(data) == 0 {
		// ServerHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) != extensionsLength {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionSessionTicket:
			if length > 0 {
				return false
			}
			m.ticketSupported = true
		}
		data = data[length:]
	}

	return true
}

type serverKeyExchangeMsg struct {
	raw []byte
	N   []byte
	g   []byte
	s   []byte
	B   []byte
}

func (m *serverKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*serverKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.N, m1.N) &&
		bytes.Equal(m.g, m1.g) &&
		bytes.Equal(m.s, m1.s) &&
		bytes.Equal(m.B, m1.B)
}

func (m *serverKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	length := 2 + len(m.N) + 2 + len(m.g) + 1 + len(m.s) + 2 + len(m.B)
	buf := make([]byte, length+4)

	x := buf
	x[0] = typeServerKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x = x[4:]

	x[0] = uint8(len(m.N) >> 8)
	x[1] = uint8(len(m.N))
	copy(x[2:], m.N)
	x = x[2+len(m.N):]

	x[0] = uint8(len(m.g) >> 8)
	x[1] = uint8(len(m.g))
	copy(x[2:], m.g)
	x = x[2+len(m.g):]

	x[0] = uint8(len(m.s))
	copy(x[1:], m.s)
	x = x[1+len(m.s):]

	x[0] = uint8(len(m.B) >> 8)
	x[1] = uint8(len(m.B))
	copy(x[2:], m.B)
	x = x[2+len(m.B):]

	m.raw = buf
	return buf
}

func (m *serverKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	data = data[4:]

	if len(data) < 2 {
		return false
	}
	Nsz := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < Nsz {
		return false
	}
	m.N, data = data[:Nsz], data[Nsz:]

	if len(data) < 2 {
		return false
	}
	gsz := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < gsz {
		return false
	}
	m.g, data = data[:gsz], data[gsz:]

	if len(data) < 1 {
		return false
	}
	ssz := int(data[0])
	data = data[1:]
	if len(data) < ssz {
		return false
	}
	m.s, data = data[:ssz], data[ssz:]

	if len(data) < 2 {
		return false
	}
	Bsz := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < Bsz {
		return false
	}
	m.B, data = data[:Bsz], data[Bsz:]

	if len(data) != 0 {
		return false
	}
	return true
}

type serverHelloDoneMsg struct{}

func (m *serverHelloDoneMsg) equal(i interface{}) bool {
	_, ok := i.(*serverHelloDoneMsg)
	return ok
}

func (m *serverHelloDoneMsg) marshal() []byte {
	x := make([]byte, 4)
	x[0] = typeServerHelloDone
	return x
}

func (m *serverHelloDoneMsg) unmarshal(data []byte) bool {
	return len(data) == 4
}

type clientKeyExchangeMsg struct {
	raw []byte
	A   []byte
}

func (m *clientKeyExchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*clientKeyExchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.A, m1.A)
}

func (m *clientKeyExchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := 2 + len(m.A)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(len(m.A) >> 8)
	x[5] = uint8(len(m.A))
	copy(x[6:], m.A)

	m.raw = x
	return x
}

func (m *clientKeyExchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	data = data[4:]

	if len(data) < 2 {
		return false
	}
	l := int(data[0])<<8 | int(data[1])
	if len(data) != 2+l {
		return false
	}
	m.A = data[2 : 2+l]
	return true
}

type finishedMsg struct {
	raw        []byte
	verifyData []byte
}

func (m *finishedMsg) equal(i interface{}) bool {
	m1, ok := i.(*finishedMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.verifyData, m1.verifyData)
}

func (m *finishedMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	x = make([]byte, 4+len(m.verifyData))
	x[0] = typeFinished
	x[3] = byte(len(m.verifyData))
	copy(x[4:], m.verifyData)
	m.raw = x
	return
}

func (m *finishedMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	m.verifyData = data[4:]
	return true
}

type newSessionTicketMsg struct {
	raw    []byte
	ticket []byte
}

func (m *newSessionTicketMsg) equal(i interface{}) bool {
	m1, ok := i.(*newSessionTicketMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ticket, m1.ticket)
}

func (m *newSessionTicketMsg) marshal() (x []byte) {
	if m.raw != nil {
		return m.raw
	}

	// See http://tools.ietf.org/html/rfc5077#section-3.3
	ticketLen := len(m.ticket)
	length := 2 + 4 + ticketLen
	x = make([]byte, 4+length)
	x[0] = typeNewSessionTicket
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[8] = uint8(ticketLen >> 8)
	x[9] = uint8(ticketLen)
	copy(x[10:], m.ticket)

	m.raw = x

	return
}

func (m *newSessionTicketMsg) unmarshal(data []byte) bool {
	m.raw = data

	if len(data) < 10 {
		return false
	}

	length := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if uint32(len(data))-4 != length {
		return false
	}

	ticketLen := int(data[8])<<8 + int(data[9])
	if len(data)-10 != ticketLen {
		return false
	}

	m.ticket = data[10:]

	return true
}

func eqUint16s(x, y []uint16) bool {
	if len(x) != len(y) {
		return false
	}
	for i, v := range x {
		if y[i] != v {
			return false
		}
	}
	return true
}
