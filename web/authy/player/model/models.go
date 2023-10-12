package models

type Users struct {
	Username    string `json:"username"`
	Firstname   string `json:"firstname,omitempty"`
	Lastname    string `json:"lastname,omitempty"`
	Password    string `json:"password,omitempty"`
	Token       string `json:"token,omitempty"`
	DateCreated string `json:"date_created,omitempty"`
}
type Error struct {
	ResponseCode      int    `json:"rc"`
	Message           string `json:"message"`
	Detail            string `json:"detail"`
	ExternalReference string `json:"ext_ref"`
}
