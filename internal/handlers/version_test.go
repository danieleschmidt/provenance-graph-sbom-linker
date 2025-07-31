package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestVersionHandler_GetVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)
	
	handler := NewVersionHandler()
	
	router := gin.New()
	router.GET("/version", handler.GetVersion)
	
	req, _ := http.NewRequest("GET", "/version", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	assert.Contains(t, response, "version")
	assert.Contains(t, response, "commit")
	assert.Contains(t, response, "date")
}