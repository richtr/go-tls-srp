// +build ignore

// Srpexclient connects to an srpexserver and either retrieves (get) or sends (put) the file.
// It takes either "get" or "put" as parameter. For "get", it reads
// the remote file and writes it to stdout.  For "put", contents are
// read from stdin and written to the server, which will store it.
//
// User & password are hard-coded in this file.
//
// See srpexadmin.go for an example.
package main

import (
	tls "bitbucket.org/mjl/go-tls-srp"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

func get(rw io.ReadWriter) (err error) {
	b := bufio.NewReader(rw)
	_, err = io.WriteString(rw, "GET\n")
	if err != nil {
		return
	}

	s, err := b.ReadString('\n')
	if err != nil {
		return
	}
	s = strings.TrimRight(s, "\n")
	if s != "DATA" {
		err = fmt.Errorf("invalid message, expected DATA")
		return
	}
	s, err = b.ReadString('\n')
	if err != nil {
		return
	}
	s = strings.TrimRight(s, "\n")
	length, err := strconv.Atoi(s)
	if err != nil {
		return
	}
	r := io.LimitReader(b, int64(length))
	_, err = io.Copy(os.Stdout, r)
	return
}

func put(rw io.ReadWriter) (err error) {
	b := &bytes.Buffer{}
	_, err = io.Copy(b, os.Stdin)
	if err != nil {
		return
	}
	buf := b.Bytes()
	_, err = io.WriteString(rw, "PUT\n")
	if err == nil {
		_, err = fmt.Fprintf(rw, "%d\n", len(buf))
	}
	if err == nil {
		_, err = rw.Write(buf)
	}
	if err != nil {
		return err
	}

	br := bufio.NewReader(rw)
	s, err := br.ReadString('\n')
	if err != nil {
		return
	}
	s = strings.TrimRight(s, "\n")
	if s != "OK" {
		err = fmt.Errorf("no OK from server")
	}
	return
}

func main() {
	cmd := ""
	if len(os.Args) == 2 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "get", "put":
	default:
		log.Fatal(`need argument, "get" or "put"`)
	}

	config := new(tls.Config)

	config.SRPUser = "glen"
	config.SRPPassword = "glenda"

	conn, err := tls.Dial("tcp", "localhost:4445", config)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("connected")

	switch cmd {
	case "get":
		err = get(conn)
	case "put":
		err = put(conn)
	}
	if err != nil {
		log.Fatal(err)
	}
}
