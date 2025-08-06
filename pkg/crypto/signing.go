package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

type Signer interface {
	Sign(data []byte) (*types.Signature, error)
	Verify(data []byte, signature *types.Signature) error
	GetKeyID() string
}

type RSASigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

type JWTSigner struct {
	privateKey []byte
	keyID      string
	issuer     string
}

func NewRSASigner(keyID string) (*RSASigner, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &RSASigner{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
	}, nil
}

func NewRSASignerFromPEM(keyID string, privatePEM []byte) (*RSASigner, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &RSASigner{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
	}, nil
}

func (s *RSASigner) Sign(data []byte) (*types.Signature, error) {
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return &types.Signature{
		ID:        uuid.New(),
		Algorithm: types.SignatureTypeX509,
		Value:     base64.StdEncoding.EncodeToString(signature),
		KeyID:     s.keyID,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}, nil
}

func (s *RSASigner) Verify(data []byte, signature *types.Signature) error {
	if signature.Algorithm != types.SignatureTypeX509 {
		return fmt.Errorf("unsupported signature algorithm: %s", signature.Algorithm)
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature.Value)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(s.publicKey, crypto.SHA256, hash[:], signatureBytes)
}

func (s *RSASigner) GetKeyID() string {
	return s.keyID
}

func (s *RSASigner) GetPublicKeyPEM() ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}), nil
}

func NewJWTSigner(keyID, issuer string, privateKey []byte) *JWTSigner {
	return &JWTSigner{
		privateKey: privateKey,
		keyID:      keyID,
		issuer:     issuer,
	}
}

func (s *JWTSigner) Sign(data []byte) (*types.Signature, error) {
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"sub": "provenance-data",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
		"jti": uuid.New().String(),
		"data": base64.StdEncoding.EncodeToString(data),
		"hash": fmt.Sprintf("%x", sha256.Sum256(data)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = s.keyID

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	return &types.Signature{
		ID:        uuid.New(),
		Algorithm: types.SignatureTypeJWT,
		Value:     tokenString,
		KeyID:     s.keyID,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"issuer": s.issuer,
		},
	}, nil
}

func (s *JWTSigner) Verify(data []byte, signature *types.Signature) error {
	if signature.Algorithm != types.SignatureTypeJWT {
		return fmt.Errorf("unsupported signature algorithm: %s", signature.Algorithm)
	}

	token, err := jwt.Parse(signature.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.privateKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return fmt.Errorf("invalid JWT token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid JWT claims")
	}

	dataB64, ok := claims["data"].(string)
	if !ok {
		return fmt.Errorf("missing data claim in JWT")
	}

	signedData, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return fmt.Errorf("failed to decode data from JWT: %w", err)
	}

	if string(signedData) != string(data) {
		return fmt.Errorf("data mismatch in JWT signature")
	}

	hashClaim, ok := claims["hash"].(string)
	if !ok {
		return fmt.Errorf("missing hash claim in JWT")
	}

	expectedHash := fmt.Sprintf("%x", sha256.Sum256(data))
	if hashClaim != expectedHash {
		return fmt.Errorf("hash mismatch in JWT signature")
	}

	return nil
}

func (s *JWTSigner) GetKeyID() string {
	return s.keyID
}

type AttestationSigner struct {
	signer Signer
}

func NewAttestationSigner(signer Signer) *AttestationSigner {
	return &AttestationSigner{signer: signer}
}

func (a *AttestationSigner) SignAttestation(attestation *types.Attestation) error {
	predicateBytes, err := json.Marshal(attestation.Predicate)
	if err != nil {
		return fmt.Errorf("failed to marshal predicate: %w", err)
	}

	signature, err := a.signer.Sign(predicateBytes)
	if err != nil {
		return fmt.Errorf("failed to sign attestation: %w", err)
	}

	attestation.Signature = signature
	return nil
}

func (a *AttestationSigner) VerifyAttestation(attestation *types.Attestation) error {
	if attestation.Signature == nil {
		return fmt.Errorf("attestation has no signature")
	}

	predicateBytes, err := json.Marshal(attestation.Predicate)
	if err != nil {
		return fmt.Errorf("failed to marshal predicate: %w", err)
	}

	return a.signer.Verify(predicateBytes, attestation.Signature)
}

type CosignCompatibleSigner struct {
	signer Signer
}

func NewCosignCompatibleSigner(signer Signer) *CosignCompatibleSigner {
	return &CosignCompatibleSigner{signer: signer}
}

func (c *CosignCompatibleSigner) SignArtifact(artifact *types.Artifact) (*types.Signature, error) {
	payload := map[string]interface{}{
		"critical": map[string]interface{}{
			"identity": map[string]interface{}{
				"docker-reference": artifact.Name + ":" + artifact.Version,
			},
			"image": map[string]interface{}{
				"docker-manifest-digest": artifact.Hash,
			},
			"type": "cosign container image signature",
		},
		"optional": map[string]interface{}{
			"creator": "provenance-linker",
			"timestamp": time.Now().Unix(),
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cosign payload: %w", err)
	}

	signature, err := c.signer.Sign(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign artifact: %w", err)
	}

	signature.Algorithm = types.SignatureTypeCosign
	signature.Metadata["cosign_compatible"] = "true"

	return signature, nil
}

func (c *CosignCompatibleSigner) VerifyArtifact(artifact *types.Artifact, signature *types.Signature) error {
	if signature.Algorithm != types.SignatureTypeCosign {
		return fmt.Errorf("not a cosign signature")
	}

	payload := map[string]interface{}{
		"critical": map[string]interface{}{
			"identity": map[string]interface{}{
				"docker-reference": artifact.Name + ":" + artifact.Version,
			},
			"image": map[string]interface{}{
				"docker-manifest-digest": artifact.Hash,
			},
			"type": "cosign container image signature",
		},
		"optional": map[string]interface{}{
			"creator": "provenance-linker",
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal cosign payload: %w", err)
	}

	return c.signer.Verify(payloadBytes, signature)
}

func SignArtifactHash(artifact *types.Artifact) string {
	data := fmt.Sprintf("%s:%s:%s", artifact.Name, artifact.Version, artifact.Hash)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("sha256:%x", hash)
}

func VerifyIntegrity(data []byte, expectedHash string) error {
	if expectedHash == "" {
		return fmt.Errorf("expected hash is empty")
	}

	actualHash := sha256.Sum256(data)
	actualHashStr := fmt.Sprintf("sha256:%x", actualHash)

	if actualHashStr != expectedHash {
		return fmt.Errorf("integrity check failed: expected %s, got %s", expectedHash, actualHashStr)
	}

	return nil
}