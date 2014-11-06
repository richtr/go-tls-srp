// +build ignore

// Example of how to connect to an TLS-SRP server.
package main

import (
	tls "bitbucket.org/mjl/go-tls-srp"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	config := new(tls.Config)
	config.SRPUser = "glen"
	config.SRPPassword = "glenda"

	// explicitly set SNI server name (instead of automatic from dial string):
	// config.ServerName = "remotehost"

	// only allow specific groups (instead of all from the TLS-SRP RFC):
	// config.SRPGroups = []*tls.SRPGroup{&tls.SRPGroup1024}

	switch len(os.Args) {
	case 1:
	case 3:
		config.SRPUser = os.Args[1]
		config.SRPPassword = os.Args[2]
	default:
		fmt.Fprintf(os.Stderr, "usage: srpdial [user password]\n")
		os.Exit(1)
	}

	conn, err := tls.Dial("tcp", "localhost:4444", config)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("connected")
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		if err != nil {
			log.Println("write", err)
		}
	}()
	_, err = io.Copy(os.Stdout, conn)
	if err != nil {
		log.Println("read", err)
	}
}
