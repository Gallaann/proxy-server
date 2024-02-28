package model

type Response struct {
	ID      string
	Code    int
	Message string
	Body    string
	Headers map[string][]string
}
