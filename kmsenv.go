package kmsenv

import (
	cloudkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/cockroachdb/errors"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"os"
	"strings"
)

// c.f. https://pkg.go.dev/google.golang.org/api/cloudkms/v1?tab=doc#pkg-constants
const (
	// View and manage your keys and secrets stored in Cloud Key Management
	// Service
	cloudkmsScope = "https://www.googleapis.com/auth/cloudkms"
)

// KmsEnv manages kms decryption
type KmsEnv struct {
	KeyringKeyName string
	client         KmsClient
	ctx            *context.Context
}

// NewKmsEnv creates a new KmsEnv instance
func NewKmsEnv(keyringKeyName string) (*KmsEnv, error) {
	ctx := context.Background()

	creds, err := google.FindDefaultCredentials(ctx, cloudkmsScope)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	client, err := cloudkms.NewKeyManagementClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &KmsEnv{KeyringKeyName: keyringKeyName, client: client, ctx: &ctx}, nil
}

// GetFromEnvOrKms returns value either env or KMS
func (k *KmsEnv) GetFromEnvOrKms(key string, required bool) (string, error) {
	if os.Getenv(key) != "" {
		return strings.TrimSpace(os.Getenv(key)), nil
	}

	kmsKey := "KMS_" + key

	if os.Getenv(kmsKey) != "" {
		return k.GetFromKms(kmsKey)
	}

	if required {
		return "", fmt.Errorf("either %s or %s is required", key, kmsKey)
	}

	return "", nil
}

// GetFromKms returns value from KMS
func (k *KmsEnv) GetFromKms(kmsKey string) (string, error) {
	value, err := k.decrypt(os.Getenv(kmsKey))

	if err != nil {
		return "", errors.WithStack(err)
	}

	return strings.TrimSpace(value), nil
}

func (k *KmsEnv) decrypt(base64Value string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil {
		return "", errors.WithStack(err)
	}

	if k.KeyringKeyName == "" {
		return "", fmt.Errorf("KeyringKeyName is required")
	}

	// Build the request.
	req := &kmspb.DecryptRequest{
		Name:       k.KeyringKeyName,
		Ciphertext: ciphertext,
	}
	// Call the API.
	resp, err := k.client.Decrypt(*k.ctx, req)
	if err != nil {
		return "", errors.WithStack(err)
	}
	return string(resp.Plaintext), nil
}
