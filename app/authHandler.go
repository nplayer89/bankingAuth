package app

import (
	"bankingAuth/dto"
	"bankingAuth/logger"
	"bankingAuth/service"
	"encoding/json"
	"net/http"
)

type AuthHandler struct {
	service service.AuthService
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := h.service.Login(loginRequest)
		if appErr != nil {
			writeResponseJson(w, appErr.Code, appErr.AsMessage())
		} else {
			writeResponseJson(w, http.StatusOK, *token)
		}
	}
}

func (h AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {

	var refreshRequest dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		logger.Error("Error while decoding refresh token request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := h.service.Refresh(refreshRequest)
		if appErr != nil {
			writeResponseJson(w, appErr.Code, appErr.AsMessage)
		} else {
			writeResponseJson(w, http.StatusOK, *token)
		}
	}
}

func writeResponseJson(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}

func (h AuthHandler) NotImplementedHandler(w http.ResponseWriter, r *http.Request) {
	writeResponseJson(w, http.StatusOK, "Handler not implemented...")
}
