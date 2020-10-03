package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"proxy/internal/pkg/generation"
)

func main() {
	keyFile  := path.Join("./", "example-ca-key.pem")
	certFile := path.Join("./", "example-ca-cert.pem")

	err := os.MkdirAll(".", 0700)
	if err != nil {
		panic(err)
	}
	h, _ := os.Hostname()

	certPEM, keyPEM, err := generation.GenCA(h)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile(certFile, certPEM, 0400)
	if err == nil {
		err = ioutil.WriteFile(keyFile, keyPEM, 0400)
		if err != nil {
			panic(err)
		}
	} else {
		panic(err)
	}
}
