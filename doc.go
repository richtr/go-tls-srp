/*
Package tls partially implements TLS-SRP as specified in RFC 5054.

TLS-SRP lets a client make a secure, authenticated TLS (SSL)
connection to a server with only a username and password. No
certificates are needed. No certificate authorities have to be
trusted.

This implementation is based on a stripped down version of Go's
crypto/tls package.  Only the non-certificate ciphers from RFC 5054
are supported, in order of preference:

	- SRP-SHA1 with AES-256-CBC,SHA1
	- SRP-SHA1 with AES-128-CBC,SHA1
	- SRP-SHA1 with 3DES-CBC,SHA1

Supported TLS extensions:

	- SNI, server name indication
	- Ticket sessions
	- SRP (obviously)

Usage is very similar to crypto/tls. However, you must always pass
the Conn-functions a valid Config. For server configs, you must set
SRPLookup, SRPSaltKey and SRPSaltSize. For client configs, you must set
SRPUser and SRPPassword.

For a minimal example of a client and server, see ex/srpdial.go and ex/srplisten.go.
For a more complete example, see ex/srpexserver.go, ex/srpexadmin.go and ex/srpexclient.go.
*/
package tls
