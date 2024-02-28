package main

import (
	"fmt"
	"os"
	"security/proxy_server"
	"security/store"
	"strconv"
)

func main() {
	httpsEnv := os.Getenv("HTTPS")
	httpsFlag, err := strconv.ParseBool(httpsEnv)
	if err != nil {
		panic(err)
	}

	storage, err := store.NewStore()
	if err != nil {
		panic(err)
	}

	server := proxy_server.NewServer(storage)

	if httpsFlag {
		fmt.Println("HTTPS PROXY STARTED")
		server.StartServerTLS()
	}

	fmt.Println("HTTP PROXY STARTED")
	server.StartServer()
}
