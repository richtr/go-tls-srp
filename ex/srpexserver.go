// +build ignore

// Srpexserver stores or retrieves a file to a user authenticated over TLS-SRP.
// Create accounts with srpexadmin first.
// Connect using srpexclient.
//
// Example:
//
//	srpexadmin glen  # you will be prompted for a password, make it "glenda"
//	srpexserver &  # will listen on localhost:4445
//
//	echo store this | srpexclient put  # stores "store this\n" on the server; user/password are hardcoded in srpexclient
//	srpexclient get  # retrieves the content, writing to stdout
//
package main

import (
	tls "bitbucket.org/mjl/go-tls-srp"
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

// group used for the verifier, must be the same as used for generating the verifier with srpexadmin
var srpGroup tls.SRPGroup

type lookup struct{}

func (l lookup) Lookup(User string) (v, s []byte, grp tls.SRPGroup, err error) {
	// return values:
	// grp should always be set.
	// if err is set, an error occurred.
	// v may be nil (no user found).

	grp = srpGroup

	base := fmt.Sprintf("./srpex/%s", User)
	if strings.Contains(base, "/../") {
		err = fmt.Errorf("bad username")
		return
	}
	s, err = ioutil.ReadFile(base + ".salt")
	if err == nil {
		v, err = ioutil.ReadFile(base + ".verifier")
	}
	// when account is invalid, do not return error (aborting connection).
	// instead, the library will pretend the user exists.
	if err != nil {
		s = nil
		v = nil
		err = nil
	}
	return
}

func get(conn *tls.Conn) (err error) {
	state := conn.ConnectionState()
	path := fmt.Sprintf("./srpex/%s.data", state.SRPUser)
	buf, err := ioutil.ReadFile(path)
	if err == nil {
		_, err = io.WriteString(conn, "DATA\n")
	}
	if err == nil {
		_, err = fmt.Fprintf(conn, "%d\n", len(buf))
	}
	if err == nil {
		_, err = conn.Write(buf)
	}
	return err
}

func put(b *bufio.Reader, conn *tls.Conn) (err error) {
	s, err := b.ReadString('\n')
	if err != nil {
		return
	}
	s = strings.TrimRight(s, "\n")
	length, err := strconv.Atoi(s)
	if err != nil {
		return
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(b, buf)
	if err != nil {
		return
	}

	state := conn.ConnectionState()
	path := fmt.Sprintf("./srpex/%s.data", state.SRPUser)
	err = ioutil.WriteFile(path, buf, os.FileMode(0600))
	if err != nil {
		return
	}

	_, err = io.WriteString(conn, "OK\n")
	return
}

func serve(conn *tls.Conn) {
	defer conn.Close()

	log.Println("new connection")
	b := bufio.NewReader(conn)
	for {
		// in put & get, we use ConnectionState().SRPUser.
		// the connection will be initialized (handshaked)
		// by then, because the following read will not return
		// before the connection has been initialized.

		s, err := b.ReadString('\n')
		if err != nil {
			log.Println(err)
			return
		}
		s = strings.TrimRight(s, "\n")
		switch s {
		case "GET":
			err = get(conn)
		case "PUT":
			err = put(b, conn)
		default:
			err = fmt.Errorf("unknown command", s)
		}
		if err != nil {
			log.Println(err)
			return
		}
	}
}

func main() {
	config := new(tls.Config)
	config.SRPLookup = lookup{}
	config.SRPSaltKey = "taiX9qui eP8iesoh ahrae9Yu eiK3ap2b"
	config.SRPSaltSize = 16 // same as in srpexadmin.go

	srpGroup = tls.SRPGroup4096

	l, err := tls.Listen("tcp", "localhost:4445", config)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept", err)
		}
		go serve(conn.(*tls.Conn))
	}
}
