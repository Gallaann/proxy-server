package api_server

import (
	"github.com/labstack/echo/v4"
	"security/api_server/handler"
	"security/store"
)

type Server struct {
	store store.Store
}

func NewServer(store store.Store) Server {
	return Server{store: store}
}

func (s Server) StartServer() {
	apiServerHandler := handler.NewHandler(s.store)

	e := echo.New()

	e.GET("/requests", apiServerHandler.GetRequests)
	e.GET("/requests/:id", apiServerHandler.GetRequestByID)
	e.GET("/repeat/:id", apiServerHandler.RepeatRequestByID)
	e.GET("/scan/:id", apiServerHandler.ScanRequestByID)

	e.Logger.Fatal(e.Start(":8001"))
}
