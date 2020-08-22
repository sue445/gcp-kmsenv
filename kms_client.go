package kmsenv

import (
	"context"
	"github.com/googleapis/gax-go/v2"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type KmsClient interface {
	// ref. https://pkg.go.dev/cloud.google.com/go/kms/apiv1?tab=doc#example-KeyManagementClient.Decrypt
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest, opts ...gax.CallOption) (*kmspb.DecryptResponse, error)
}
