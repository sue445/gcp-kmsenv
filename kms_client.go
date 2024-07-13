package kmsenv

import (
	"cloud.google.com/go/kms/apiv1/kmspb"
	"context"
	"github.com/googleapis/gax-go/v2"
)

// KmsClient represents KeyManagementClient interface for stub
type KmsClient interface {
	// ref. https://pkg.go.dev/cloud.google.com/go/kms/apiv1?tab=doc#example-KeyManagementClient.Decrypt
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}
