package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) CreateArtifact(ctx context.Context, artifact *types.Artifact) error {
	args := m.Called(ctx, artifact)
	return args.Error(0)
}

func (m *MockDatabase) GetArtifact(ctx context.Context, id string) (*types.Artifact, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Artifact), args.Error(1)
}

func (m *MockDatabase) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestArtifactHandler_CreateArtifact(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		mockSetup      func(*MockDatabase)
		expectedError  string
	}{
		{
			name: "Valid artifact creation",
			requestBody: map[string]interface{}{
				"name":     "test-artifact",
				"version":  "1.0.0",
				"type":     "container",
				"hash":     "sha256:abc123",
				"size":     1024,
				"metadata": map[string]string{"env": "test"},
			},
			expectedStatus: http.StatusCreated,
			mockSetup: func(db *MockDatabase) {
				db.On("CreateArtifact", mock.Anything, mock.Anything).Return(nil)
			},
		},
		{
			name: "Missing required fields",
			requestBody: map[string]interface{}{
				"name": "test-artifact",
			},
			expectedStatus: http.StatusBadRequest,
			mockSetup:      func(db *MockDatabase) {},
			expectedError:  "Key: 'version' Error:Field validation for 'version' failed on the 'required' tag",
		},
		{
			name:           "Invalid JSON",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			mockSetup:      func(db *MockDatabase) {},
		},
		{
			name: "Database error",
			requestBody: map[string]interface{}{
				"name":    "test-artifact",
				"version": "1.0.0",
				"type":    "container",
			},
			expectedStatus: http.StatusInternalServerError,
			mockSetup: func(db *MockDatabase) {
				db.On("CreateArtifact", mock.Anything, mock.Anything).Return(assert.AnError)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := new(MockDatabase)
			tt.mockSetup(mockDB)

			handler := NewArtifactHandler(mockDB)

			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				jsonData, _ := json.Marshal(tt.requestBody)
				body.Write(jsonData)
			}

			req, _ := http.NewRequest(http.MethodPost, "/artifacts", &body)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			handler.CreateArtifact(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var response map[string]interface{}
				json.Unmarshal(w.Body.Bytes(), &response)
				assert.Contains(t, response["error"].(string), tt.expectedError)
			}

			if tt.expectedStatus == http.StatusCreated {
				var artifact types.Artifact
				json.Unmarshal(w.Body.Bytes(), &artifact)
				assert.Equal(t, "test-artifact", artifact.Name)
				assert.Equal(t, "1.0.0", artifact.Version)
				assert.Equal(t, types.ArtifactTypeContainer, artifact.Type)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestArtifactHandler_GetArtifact(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		artifactID     string
		expectedStatus int
		mockSetup      func(*MockDatabase)
	}{
		{
			name:           "Valid artifact retrieval",
			artifactID:     "valid-id",
			expectedStatus: http.StatusOK,
			mockSetup: func(db *MockDatabase) {
				artifact := &types.Artifact{
					ID:        uuid.New(),
					Name:      "test-artifact",
					Version:   "1.0.0",
					Type:      types.ArtifactTypeContainer,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
					Metadata:  make(map[string]string),
				}
				db.On("GetArtifact", mock.Anything, "valid-id").Return(artifact, nil)
			},
		},
		{
			name:           "Artifact not found",
			artifactID:     "nonexistent-id",
			expectedStatus: http.StatusNotFound,
			mockSetup: func(db *MockDatabase) {
				db.On("GetArtifact", mock.Anything, "nonexistent-id").Return(nil, assert.AnError)
			},
		},
		{
			name:           "Empty artifact ID",
			artifactID:     "",
			expectedStatus: http.StatusBadRequest,
			mockSetup:      func(db *MockDatabase) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := new(MockDatabase)
			tt.mockSetup(mockDB)

			handler := NewArtifactHandler(mockDB)

			req, _ := http.NewRequest(http.MethodGet, "/artifacts/"+tt.artifactID, nil)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			c.Params = []gin.Param{{Key: "id", Value: tt.artifactID}}

			handler.GetArtifact(c)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedStatus == http.StatusOK {
				var artifact types.Artifact
				json.Unmarshal(w.Body.Bytes(), &artifact)
				assert.Equal(t, "test-artifact", artifact.Name)
			}

			mockDB.AssertExpectations(t)
		})
	}
}

func TestArtifactHandler_ListArtifacts(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name         string
		queryParams  map[string]string
		expectedCode int
	}{
		{
			name:         "Default parameters",
			queryParams:  map[string]string{},
			expectedCode: http.StatusOK,
		},
		{
			name: "Custom limit and offset",
			queryParams: map[string]string{
				"limit":  "10",
				"offset": "5",
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "Invalid limit",
			queryParams: map[string]string{
				"limit": "invalid",
			},
			expectedCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDB := new(MockDatabase)
			handler := NewArtifactHandler(mockDB)

			req, _ := http.NewRequest(http.MethodGet, "/artifacts", nil)

			q := req.URL.Query()
			for key, value := range tt.queryParams {
				q.Add(key, value)
			}
			req.URL.RawQuery = q.Encode()

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			handler.ListArtifacts(c)

			assert.Equal(t, tt.expectedCode, w.Code)

			var response map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &response)

			artifacts, ok := response["artifacts"].([]interface{})
			assert.True(t, ok)
			assert.Len(t, artifacts, 1)

			total, ok := response["total"].(float64)
			assert.True(t, ok)
			assert.Equal(t, float64(1), total)

			mockDB.AssertExpectations(t)
		})
	}
}

func BenchmarkArtifactHandler_CreateArtifact(b *testing.B) {
	gin.SetMode(gin.TestMode)

	mockDB := new(MockDatabase)
	mockDB.On("CreateArtifact", mock.Anything, mock.Anything).Return(nil)

	handler := NewArtifactHandler(mockDB)

	requestBody := map[string]interface{}{
		"name":     "benchmark-artifact",
		"version":  "1.0.0",
		"type":     "container",
		"hash":     "sha256:abc123",
		"size":     1024,
		"metadata": map[string]string{"env": "test"},
	}

	jsonData, _ := json.Marshal(requestBody)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		body := bytes.NewBuffer(jsonData)
		req, _ := http.NewRequest(http.MethodPost, "/artifacts", body)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		handler.CreateArtifact(c)

		if w.Code != http.StatusCreated {
			b.Fatalf("Expected status 201, got %d", w.Code)
		}
	}
}

func TestArtifactHandler_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockDB := new(MockDatabase)
	handler := NewArtifactHandler(mockDB)

	artifactID := uuid.New().String()
	artifact := &types.Artifact{
		ID:        uuid.MustParse(artifactID),
		Name:      "integration-test-artifact",
		Version:   "1.0.0",
		Type:      types.ArtifactTypeContainer,
		Hash:      "sha256:def456",
		Size:      2048,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  map[string]string{"test": "integration"},
	}

	mockDB.On("CreateArtifact", mock.Anything, mock.Anything).Return(nil).Once()
	mockDB.On("GetArtifact", mock.Anything, mock.Anything).Return(artifact, nil).Once()

	t.Run("Create and retrieve artifact", func(t *testing.T) {
		requestBody := map[string]interface{}{
			"name":     artifact.Name,
			"version":  artifact.Version,
			"type":     string(artifact.Type),
			"hash":     artifact.Hash,
			"size":     artifact.Size,
			"metadata": artifact.Metadata,
		}

		jsonData, _ := json.Marshal(requestBody)
		body := bytes.NewBuffer(jsonData)

		req, _ := http.NewRequest(http.MethodPost, "/artifacts", body)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		handler.CreateArtifact(c)
		assert.Equal(t, http.StatusCreated, w.Code)

		var createdArtifact types.Artifact
		json.Unmarshal(w.Body.Bytes(), &createdArtifact)
		assert.Equal(t, artifact.Name, createdArtifact.Name)

		req, _ = http.NewRequest(http.MethodGet, "/artifacts/"+artifactID, nil)
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = req
		c.Params = []gin.Param{{Key: "id", Value: artifactID}}

		handler.GetArtifact(c)
		assert.Equal(t, http.StatusOK, w.Code)

		var retrievedArtifact types.Artifact
		json.Unmarshal(w.Body.Bytes(), &retrievedArtifact)
		assert.Equal(t, artifact.Name, retrievedArtifact.Name)
		assert.Equal(t, artifact.Version, retrievedArtifact.Version)
	})

	mockDB.AssertExpectations(t)
}