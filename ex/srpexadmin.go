// +build ignore

// Srpexadmin takes a username as parameter and reads a password from stdin,
// then writes a random salt and the SRP verifier to ./srpex/<user>.{salt,verifier}.
//
// See srpexserver.go for an example.
package main

import (
	tls "bitbucket.org/mjl/go-tls-srp"
	"bufio"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: srpexadmin user\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	user := os.Args[1]
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("Password (will echo):")
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	password = strings.TrimRight(password, "\n")
	fmt.Printf("Writing SRP verifier for user %q, password %q, salt %x\n", user, password, salt)
	v := tls.SRPVerifier(user, password, salt, tls.SRPGroup4096)
	err = ioutil.WriteFile(fmt.Sprintf("./srpex/%s.salt", user), salt, os.FileMode(0600))
	if err == nil {
		err = ioutil.WriteFile(fmt.Sprintf("./srpex/%s.verifier", user), v, os.FileMode(0600))
	}
	if err != nil {
		log.Fatal(err)
	}
}
