package database

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"sync"
)

type DB struct {
	db *mongo.Database
	mu *sync.Mutex
	id int
}

func NewDB(db *mongo.Database, mu *sync.Mutex, id int) *DB {
	return &DB {
		db,
		mu,
		id,
	}
}

type Record struct {
	Id int
	Req string
	Host string
	Scheme string
	Vulnerabilities []string
}

func (db *DB) Insert(req Record) (interface{}, error) {

	c := db.db.Collection("requests")
	db.mu.Lock()
	db.id++
	req.Id = db.id
	db.mu.Unlock()
	res, err := c.InsertOne(context.TODO(), req)
	if err != nil {
		fmt.Println("jfsds")
		return 0, err
	}
	fmt.Println("nnnnnnnnnnnnnnnnnnn")
	return res.InsertedID, nil
}

func (db *DB) Find(id int) (*Record, error) {
	req := &Record{}
	c := db.db.Collection("requests")
	err := c.FindOne(context.TODO(), bson.M{"id": id}).Decode(&req)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (db *DB) Select() ([]*Record, error) {
	reqs := make([]*Record, 0)

	c := db.db.Collection("requests")
	findOptions := options.Find()
	findOptions.SetLimit(500)

	cur, err := c.Find(context.TODO(), bson.D{{}}, findOptions)
	if err != nil {
		return nil, err
	}
	for cur.Next(context.TODO()) {
		elem := &Record{}
		err := cur.Decode(elem)
		if err != nil {
			return nil, err
		}

		reqs = append(reqs, elem)
	}

	if err := cur.Err(); err != nil {
		return nil, err
	}

	// Close the cursor once finished
	cur.Close(context.TODO())

	//fmt.Printf("Found multiple document: %+v\n", results)

	return reqs, nil
}
