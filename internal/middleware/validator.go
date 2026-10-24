package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// APIResponse standardizes JSON responses and omits empty data/error fields.
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Code    string      `json:"code,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, payload APIResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func DecodeAndValidate(r *http.Request, dst interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return validate.Struct(dst)
}
