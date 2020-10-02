package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	"proxy/internal/pkg/database"
	"proxy/internal/pkg/proxy"
	"sync"
)

func main() {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
	if err != nil {
		log.Fatal(err)
	}

	// Create connect
	err = client.Connect(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	db := client.Database("requestsDB")
	mu := &sync.Mutex{}
	id := 0
	d := database.NewDB(db, mu, id)

	cer, err := tls.LoadX509KeyPair("nn-ca-cert.pem", "nn-ca-key.pem")
	if err != nil {
		log.Println( err)
		return
	}
	cer.Leaf, err = x509.ParseCertificate(cer.Certificate[0])

	h := proxy.NewHandler(&cer, &tls.Config{}, d)
	server := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				h.HttpsHandler(w, r)
			} else {
				h.HttpHandler(w, r)
			}
		}),
		}


	log.Fatal(server.ListenAndServe())

}
