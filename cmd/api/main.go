package main

import (
	"security/api_server"
	"security/store"
)

func main() {
	storage, err := store.NewStore()
	if err != nil {
		panic(err)
	}

	server := api_server.NewServer(storage)

	server.StartServer()
}
