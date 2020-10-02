package main

import (
	"context"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	"proxy/internal/pkg/database"
	"proxy/internal/pkg/repeater"
	"sync"
	"time"
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

	h := repeater.NewHandler(d)

	r := mux.NewRouter()

	r.HandleFunc("/requests", h.GetRequests)
	r.HandleFunc("/requests/{id:[0-9]+}", h.SendRequest)

	srv := &http.Server{
		Handler:      r,
		Addr:         "127.0.0.1:8081",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	srv.ListenAndServe()
}
