package store

import (
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/net/context"
	"net/http"
	"security/model"
	"security/parser"
)

type Store struct {
	client             *mongo.Client
	requestCollection  *mongo.Collection
	responseCollection *mongo.Collection
}

func NewStore() (Store, error) {
	clientOptions := options.Client().ApplyURI("mongodb://root:root@mongo:27017")

	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return Store{}, err
	}

	requestCollection := client.Database("admin").Collection("request")
	responseCollection := client.Database("admin").Collection("response")

	return Store{client: client, requestCollection: requestCollection, responseCollection: responseCollection}, nil
}

func (s *Store) SaveRequest(req *http.Request) {
	parsedReq := parser.ParseRequest(req)
	parsedReq.ID = uuid.NewString()

	_, err := s.requestCollection.InsertOne(context.TODO(), parsedReq)
	if err != nil {
		panic(err)
	}
}

func (s *Store) SaveResponse(resp *http.Response) {
	parsedResp := parser.ParseResponse(resp)
	parsedResp.ID = uuid.NewString()

	_, err := s.responseCollection.InsertOne(context.TODO(), parsedResp)
	if err != nil {
		panic(err)
	}
}

func (s *Store) GetRequests() []model.Request {
	var requests []model.Request

	cursor, err := s.requestCollection.Find(context.TODO(), bson.D{})
	if err != nil {
		panic(err)
	}

	err = cursor.All(context.TODO(), &requests)
	if err != nil {
		panic(err)
	}

	return requests
}

func (s *Store) GetRequestByID(id string) model.Request {
	var request model.Request

	err := s.requestCollection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&request)
	if err != nil {
		panic(err)
	}

	return request
}
