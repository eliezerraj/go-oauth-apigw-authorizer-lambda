package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/model"
	"github.com/go-oauth-apigw-authorizer-lambda/internal/core/erro"
	"github.com/gorilla/mux"
)

// About create a new credential
func (h *HttpRouters) SignIn(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("SignIn")

	//trace
	span := tracerProvider.Span(req.Context(), "adapter.api.SignIn")
	defer span.End()

	// prepare body
	credential := model.Credential{}
	err := json.NewDecoder(req.Body).Decode(&credential)
    if err != nil {
		core_apiError = core_apiError.NewAPIError(err, http.StatusBadRequest)
		return &core_apiError
    }
	defer req.Body.Close()

	//call service
	res, err := h.workerService.SignIn(req.Context(), credential)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			core_apiError = core_apiError.NewAPIError(err, http.StatusNotFound)
		default:
			core_apiError = core_apiError.NewAPIError(err, http.StatusInternalServerError)
		}
		return &core_apiError
	}
	
	return core_json.WriteJSON(rw, http.StatusOK, res)
}

// About add a scope
func (h *HttpRouters) AddScope(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("AddScope")

	//trace
	span := tracerProvider.Span(req.Context(), "adapter.api.AddScope")
	defer span.End()

	// prepare body
	credential_scope := model.CredentialScope{}
	err := json.NewDecoder(req.Body).Decode(&credential_scope)
    if err != nil {
		core_apiError = core_apiError.NewAPIError(err, http.StatusBadRequest)
		return &core_apiError
    }
	defer req.Body.Close()

	//call service
	res, err := h.workerService.AddScope(req.Context(), credential_scope)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			core_apiError = core_apiError.NewAPIError(err, http.StatusNotFound)
		default:
			core_apiError = core_apiError.NewAPIError(err, http.StatusInternalServerError)
		}
		return &core_apiError
	}
	
	return core_json.WriteJSON(rw, http.StatusOK, res)
}

// About add a scope
func (h *HttpRouters) GetCredential(rw http.ResponseWriter, req *http.Request) error {
	childLogger.Debug().Msg("AddScope")

	//trace
	span := tracerProvider.Span(req.Context(), "adapter.api.GetCredential")
	defer span.End()

	//parameters
	vars := mux.Vars(req)
	varID := vars["id"]

	credential := model.Credential{ User: varID}

	//call service
	res, err := h.workerService.GetCredential(req.Context(), credential)
	if err != nil {
		switch err {
		case erro.ErrNotFound:
			core_apiError = core_apiError.NewAPIError(err, http.StatusNotFound)
		default:
			core_apiError = core_apiError.NewAPIError(err, http.StatusInternalServerError)
		}
		return &core_apiError
	}
	
	return core_json.WriteJSON(rw, http.StatusOK, res)
}