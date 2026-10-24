package handlers

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/stkrfx/poshak-attendance/internal/middleware"
	"github.com/stkrfx/poshak-attendance/internal/models"
	"gorm.io/gorm"
)

type UserDocumentHandler struct {
	db *gorm.DB
}

func NewUserDocumentHandler(db *gorm.DB) *UserDocumentHandler {
	return &UserDocumentHandler{db: db}
}

func (h *UserDocumentHandler) ListDocuments(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)

	var docs []models.UserDocument
	_ = h.db.Order("created_at DESC").Find(&docs, "user_id = ?", user.ID).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"can_upload_documents": user.CanUploadDocuments,
			"documents":            docs,
		},
	})
}

type UploadDocumentRequest struct {
	Category        string  `json:"category" validate:"required,oneof=IDENTITY CERTIFICATE"`
	DocumentType    string  `json:"document_type" validate:"required"`
	DocumentNumber  string  `json:"document_number" validate:"required"`
	InstitutionName *string `json:"institution_name,omitempty"`
	StartDate       *string `json:"start_date,omitempty"`
	EndDate         *string `json:"end_date,omitempty"`
	FileURL         string  `json:"file_url" validate:"required"`
	MimeType        string  `json:"mime_type" validate:"required"`
}

func (h *UserDocumentHandler) UploadDocument(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	if !user.CanUploadDocuments {
		middleware.WriteJSON(w, http.StatusForbidden, middleware.APIResponse{
			Success: false,
			Code:    "DOCUMENT_UPLOAD_RESTRICTED",
			Message: "Document uploads have been disabled for your account.",
		})
		return
	}

	var req UploadDocumentRequest
	if err := middleware.DecodeAndValidate(r, &req); err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Please fill in all required document details.",
		})
		return
	}

	if req.Category == "CERTIFICATE" {
		if req.InstitutionName == nil || strings.TrimSpace(*req.InstitutionName) == "" ||
			req.StartDate == nil || req.EndDate == nil {
			middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
				Success: false,
				Message: "Educational certificates require Institution Name, Start Date, and End Date.",
			})
			return
		}
	}

	doc := models.UserDocument{
		UserID:          user.ID,
		Category:        req.Category,
		DocumentType:    strings.ToUpper(strings.TrimSpace(req.DocumentType)),
		DocumentNumber:  strings.TrimSpace(req.DocumentNumber),
		InstitutionName: req.InstitutionName,
		StartDate:       req.StartDate,
		EndDate:         req.EndDate,
		FileURL:         strings.TrimSpace(req.FileURL),
		MimeType:        strings.TrimSpace(req.MimeType),
	}

	if err := h.db.Create(&doc).Error; err != nil {
		middleware.WriteJSON(w, http.StatusInternalServerError, middleware.APIResponse{
			Success: false,
			Message: "Failed to save document.",
		})
		return
	}

	middleware.WriteJSON(w, http.StatusCreated, middleware.APIResponse{
		Success: true,
		Message: "Document saved successfully.",
		Data:    doc,
	})
}

func (h *UserDocumentHandler) DeleteDocument(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetAuthenticatedUser(r)
	docID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		middleware.WriteJSON(w, http.StatusBadRequest, middleware.APIResponse{
			Success: false,
			Message: "Invalid document ID.",
		})
		return
	}

	_ = h.db.Delete(&models.UserDocument{}, "id = ? AND user_id = ?", docID, user.ID).Error

	middleware.WriteJSON(w, http.StatusOK, middleware.APIResponse{
		Success: true,
		Message: "Document removed.",
	})
}
