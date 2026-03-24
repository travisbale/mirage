package api

import (
	"errors"
	"net/http"

	"github.com/travisbale/mirage/internal/aitm"
	"github.com/travisbale/mirage/sdk"
)

func (r *Router) inviteOperator(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.InviteOperatorRequest](w, req)
	if !ok {
		return
	}

	invite, err := r.Operators.Invite(body.Name)
	if err != nil {
		if errors.Is(err, aitm.ErrConflict) {
			r.writeError(w, http.StatusConflict, "operator already exists", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to create invite", err)
		}
		return
	}

	writeJSON(w, http.StatusCreated, sdk.InviteOperatorResponse{
		Token: invite.Token,
	})
}

func (r *Router) enrollOperator(w http.ResponseWriter, req *http.Request) {
	body, ok := decodeAndValidate[sdk.EnrollRequest](w, req)
	if !ok {
		return
	}

	certPEM, caCertPEM, err := r.Operators.Enroll(body.Token, []byte(body.CSRPEM))
	if err != nil {
		switch {
		case errors.Is(err, aitm.ErrInvalidToken):
			r.writeError(w, http.StatusUnauthorized, "invalid or expired invite token", err)
		case errors.Is(err, aitm.ErrInvalidCSR):
			r.writeError(w, http.StatusBadRequest, "invalid certificate signing request", err)
		case errors.Is(err, aitm.ErrConflict):
			r.writeError(w, http.StatusConflict, "operator already exists", err)
		default:
			r.writeError(w, http.StatusInternalServerError, "enrollment failed", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, sdk.EnrollResponse{
		CertPEM:   string(certPEM),
		CACertPEM: string(caCertPEM),
	})
}

func (r *Router) listOperators(w http.ResponseWriter, req *http.Request) {
	operators, err := r.Operators.List()
	if err != nil {
		r.writeError(w, http.StatusInternalServerError, "failed to list operators", err)
		return
	}

	items := make([]sdk.OperatorResponse, len(operators))
	for i, op := range operators {
		items[i] = sdk.OperatorResponse{
			Name:      op.Name,
			CreatedAt: op.CreatedAt,
		}
	}

	writeJSON(w, http.StatusOK, sdk.OperatorList{Operators: items})
}

func (r *Router) deleteOperator(w http.ResponseWriter, req *http.Request) {
	name := req.PathValue("name")
	if err := r.Operators.Delete(name); err != nil {
		if errors.Is(err, aitm.ErrNotFound) {
			r.writeError(w, http.StatusNotFound, "operator not found", err)
		} else {
			r.writeError(w, http.StatusInternalServerError, "failed to delete operator", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
