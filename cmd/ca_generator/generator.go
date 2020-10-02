package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"proxy/internal/pkg/proxy"
)

func main() {
	keyFile  := path.Join("./", "ca-key.pem")
	certFile := path.Join("./", "ca-cert.pem")

	err := os.MkdirAll(".", 0700)
	if err != nil {
		panic(err)
	}
	h, _ := os.Hostname()

	certPEM, keyPEM, err := proxy.GenCA(h)
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
