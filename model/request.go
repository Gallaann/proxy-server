package model

type Request struct {
	ID         string              `bson:"_id,omitempty" json:"id"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	Body       string              `json:"body"`
	Cookies    map[string]string   `json:"cookies"`
	PostParams map[string]string   `json:"post_params"`
	Headers    map[string][]string `json:"headers"`
	GetParams  map[string][]string `json:"get_params"`
}
