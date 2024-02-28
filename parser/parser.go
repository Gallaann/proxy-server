package parser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"security/model"
)

func ParseRequest(req *http.Request) model.Request {
	parsedReq := model.Request{
		Method:     req.Method,
		Cookies:    make(map[string]string),
		PostParams: make(map[string]string),
		Headers:    make(map[string][]string),
		GetParams:  make(map[string][]string),
	}

	// path
	switch req.URL.Scheme {
	case "":
		parsedReq.Path = "https://" + req.URL.Host + req.URL.Path
	default:
		parsedReq.Path = req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	}

	// body
	data := make(map[string]string)
	if req.Method == http.MethodPost && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			panic(err)
		}

		err = json.Unmarshal(body, &data)
		if err != nil {
			panic(err)
		}

		parsedReq.Body = string(body)
	}

	// cookies
	for _, cookie := range req.Cookies() {
		parsedReq.Cookies[cookie.Name] = cookie.Value
	}

	// post_params
	if req.Method == http.MethodPost && req.Body != nil {
		for key, value := range data {
			parsedReq.PostParams[key] = value
		}
	}

	// headers
	for key, value := range req.Header {
		parsedReq.Headers[key] = value
	}

	// get_params
	if req.Method == http.MethodGet {
		for key, value := range req.URL.Query() {
			parsedReq.GetParams[key] = value
		}
	}

	return parsedReq
}

func ParseResponse(resp *http.Response) model.Response {
	parsedResp := model.Response{
		Code:    resp.StatusCode,
		Message: resp.Status,
		Headers: make(map[string][]string),
	}

	// headers
	for key, value := range resp.Header {
		parsedResp.Headers[key] = value
	}

	// body
	if resp.Request.Method == http.MethodPost && resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		parsedResp.Body = string(body)
	}

	return parsedResp
}

func ParseRepeatRequest(request model.Request) *http.Request {
	var err error
	var repeatRequest *http.Request

	if request.Body != "" {
		jsonData, errIn := json.Marshal(request.Body)
		if errIn != nil {
			panic(errIn)
		}

		repeatRequest, err = http.NewRequest(request.Method, request.Path, bytes.NewBuffer(jsonData))
		if err != nil {
			panic(err)
		}
	} else {
		repeatRequest, err = http.NewRequest(request.Method, request.Path, nil)
		if err != nil {
			panic(err)
		}
	}

	// cookie
	for k, v := range request.Cookies {
		repeatRequest.AddCookie(&http.Cookie{
			Name:  k,
			Value: v,
		})
	}

	// headers
	for k, v := range request.Headers {
		for _, vv := range v {
			repeatRequest.Header.Add(k, vv)
		}
	}

	return repeatRequest
}
