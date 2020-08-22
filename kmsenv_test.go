package kmsenv

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/sue445/kmsenv/mock_kmsenv"
	"google.golang.org/genproto/googleapis/cloud/kms/v1"
	"os"
	"testing"
)

func TestKmsEnv_GetFromEnvOrKms(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	stubResponse := &kms.DecryptResponse{
		Plaintext: []byte("kms_value"),
	}

	m := mock_kmsenv.NewMockKmsClient(ctrl)

	m.
		EXPECT().
		Decrypt(gomock.Any(), gomock.Any()).
		Return(stubResponse, nil).
		AnyTimes()

	ctx := context.Background()
	k := &KmsEnv{
		KeyringKeyName: "projects/PROJECT_NAME/locations/global/keyRings/KEY_RING_NAME/cryptoKeys/KEY_NAME",
		client:         m,
		ctx:            &ctx,
	}

	os.Setenv("KEY1", "env_value")
	os.Setenv("KMS_KEY2", "ZHVtbXkK") // base64 encoded "dummy" value

	type args struct {
		key      string
		required bool
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Get from env value",
			args: args{
				key:      "KEY1",
				required: true,
			},
			want: "env_value",
		},
		{
			name: "Get from KMS value",
			args: args{
				key:      "KEY2",
				required: true,
			},
			want: "kms_value",
		},
		{
			name: "optional key is not found in both env and KMS",
			args: args{
				key:      "INVALID_KEY",
				required: false,
			},
			want: "",
		},
		{
			name: "required key is not found in both env and KMS",
			args: args{
				key:      "INVALID_KEY",
				required: true,
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := k.GetFromEnvOrKms(tt.args.key, tt.args.required)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				if assert.NoError(t, err) {
					assert.Equal(t, tt.want, got)
				}
			}
		})
	}
}
