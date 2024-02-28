package proxy_server

import (
	"crypto/tls"
	"errors"
	"github.com/labstack/echo/v4"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"security/store"
)

type Proxy struct {
	store store.Store
}

func NewServer(store store.Store) Proxy {
	return Proxy{store: store}
}

func (p Proxy) StartServer() {
	e := echo.New()
	e.Any("/*", p.Handle)
	e.Logger.Fatal(e.Start(":8081"))
}

func (p Proxy) StartServerTLS() {
	e := echo.New()
	e.Any("/*", p.Handle)

	server := &http.Server{
		Addr:         ":8081",
		Handler:      e,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	err := http2.ConfigureServer(server, nil)
	if err != nil {
		panic(err)
	}

	err = server.ListenAndServeTLS("certs/server.pem", "certs/server.key")
	if err != nil {
		panic(err)
	}
}

func (p Proxy) Handle(ctx echo.Context) error {
	if ctx.Request().Method == http.MethodConnect {
		return p.HttpsHandle(ctx)
	}

	return p.HttpHandle(ctx)
}

func (p Proxy) HttpHandle(ctx echo.Context) error {
	requestUrlString := getUrlFromContext(ctx)
	requestUrl, err := url.Parse(requestUrlString)
	if err != nil {
		panic(err)
	}

	ctx.Request().URL = requestUrl
	ctx.Request().Header.Del("Proxy-Connection")

	go p.store.SaveRequest(ctx.Request())
	resp, err := http.DefaultTransport.RoundTrip(ctx.Request())
	if err != nil {
		panic(err)
	}
	go p.store.SaveResponse(resp)
	copyHeaders(ctx.Response().Header(), resp.Header)

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	_, err = ctx.Response().Write(responseBody)
	if err != nil {
		panic(err)
	}

	return ctx.JSON(http.StatusOK, ctx.Response())
}

func (p Proxy) HttpsHandle(ctx echo.Context) error {
	dest, err := net.Dial("tcp", ctx.Request().Host)
	if err != nil {
		panic(err)
	}

	hijacker, ok := ctx.Response().Writer.(http.Hijacker)
	if !ok {
		panic(errors.New("hjacker"))
	}

	client, _, err := hijacker.Hijack()
	if err != nil {
		panic(err)
	}

	go transfer(dest, client)
	go transfer(client, dest)

	return nil
}

func getUrlFromContext(ctx echo.Context) string {
	protocol := ctx.Request().URL.Scheme
	host, port, _ := net.SplitHostPort(ctx.Request().Host)
	if host == "" {
		host = ctx.Request().Host
	}

	path := ctx.Request().URL.Path

	if host == "localhost" || host == "127.0.0.1" && port == "8001" {
		host = "api:8001"
	}

	return protocol + "://" + host + path
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()

	io.Copy(destination, source)
}
