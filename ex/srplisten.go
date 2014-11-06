// +build ignore

// Example server, listening for new connections, and connecting stdin/stdout with that connection.
package main

import (
	tls "bitbucket.org/mjl/go-tls-srp"
	"io"
	"log"
	"os"
)

// WARNING: for real servers, every user should have a unique, randomly generated salt.
var Salt = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}

// WARNING: for real servers, you do not store plain text passwords anywhere.
//          you only store salts and derived verifiers (and the group, but you usually use
//          one group for all accounts, so you probably don't store it explicitly).
type TableLookup map[string]string

var usertab = TableLookup(map[string]string{
	"glen": "glenda",
	"mjl":  "test",
})

func (tl TableLookup) Lookup(user string) (v, s []byte, grp tls.SRPGroup, err error) {
	grp = tls.SRPGroup4096

	log.Println("Lookup for", user)
	p := tl[user]
	if p == "" {
		return nil, nil, grp, nil
	}
	// WARNING: for real servers, you read the verifier from a file or database,
	// because you don't want to store the password in plaintext.
	v = tls.SRPVerifier(user, p, Salt, grp)
	return v, Salt, grp, nil
}

func main() {
	config := new(tls.Config)
	config.SRPLookup = usertab

	// generate a random salt unique for your application, and keep using it
	config.SRPSaltKey = "Feiv9ahL Quiew5ai Zohs5uov aC7thi6r"

	// use the same size for the random salts for all accounts, and specify its size
	config.SRPSaltSize = len(Salt)

	l, err := tls.Listen("tcp", "localhost:4444", config)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		// immediately start a new goroutine, because the call to Handshake() will be blocking.
		// after the Handshake, SRPUser from the connection state is valid.
		go func() {
			conn := conn.(*tls.Conn)
			err := conn.Handshake()
			if err != nil {
				log.Println(err)
				return
			}
			state := conn.ConnectionState()
			log.Printf("new connection, user %q, server name %q", state.SRPUser, state.ServerName)

			go func() {
				_, err := io.Copy(conn, os.Stdin)
				if err != nil {
					log.Println(err)
				}
			}()
			_, err = io.Copy(os.Stdout, conn)
			if err != nil {
				log.Println(err)
			}
		}()
	}
}
