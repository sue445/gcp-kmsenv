# gcp-kmsenv
Detect variable from environment variable or [GCP Cloud KMS](https://cloud.google.com/security-key-management).

You can access KMS with a syntax similar to `os.Getenv`

[![Latest Version](https://img.shields.io/github/v/tag/sue445/gcp-kmsenv)](https://github.com/sue445/gcp-kmsenv/tags)
[![test](https://github.com/sue445/gcp-kmsenv/actions/workflows/test.yml/badge.svg)](https://github.com/sue445/gcp-kmsenv/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/sue445/gcp-kmsenv/badge.svg)](https://coveralls.io/github/sue445/gcp-kmsenv)
[![Maintainability](https://qlty.sh/gh/sue445/projects/gcp-kmsenv/maintainability.svg)](https://qlty.sh/gh/sue445/projects/gcp-kmsenv)
[![GoDoc](https://godoc.org/github.com/sue445/gcp-kmsenv?status.svg)](https://godoc.org/github.com/sue445/gcp-kmsenv)
[![Go Report Card](https://goreportcard.com/badge/github.com/sue445/gcp-kmsenv)](https://goreportcard.com/report/github.com/sue445/gcp-kmsenv)

## Requirements
### Base64 encoded ciphertext
Encrypt credential with `gcloud kms encrypt` and convert with base64.

e.g. 

```bash
echo -n SECRET_ACCESS_TOKEN | gcloud --project PROJECT_NAME kms encrypt --plaintext-file=- --ciphertext-file=- --location=global --keyring=KEY_RING_NAME --key=KEY_NAME | base64
```

After that, register with the environment variable starting with `KMS_`. (e.g. `KMS_ACCESS_TOKEN` )

### Service account
Add IAM role `roles/cloudkms.cryptoKeyDecrypter` to service account if necessary.

## Example
```bash
export SOME_KEY="env_value"
export KMS_ACCESS_TOKEN="base64_encoded_ciphertext"
```

```go
package main

import "github.com/sue445/gcp-kmsenv"

func main() {
    keyringKeyName := "projects/PROJECT_NAME/locations/global/keyRings/KEY_RING_NAME/cryptoKeys/KEY_NAME"
    k, err := kmsenv.NewKmsEnv(keyringKeyName)
    if err != nil {
        panic(err)
    }

    // get from environment variable
    value, err := k.GetFromEnvOrKms("SOME_KEY", false)
    // => "env_value"

    // get and decrypt from KMS
    // NOTE. prefix `KMS_` is needless
    access_token, err := k.GetFromEnvOrKms("ACCESS_TOKEN", false)
    // => "SECRET_ACCESS_TOKEN"

    // When key is not found in both environment variable and KMS, returned empty string (not error)
    value, err := k.GetFromEnvOrKms("INVALID_KEY", false)
    // => ""

    // When key is not found in both environment variable and KMS, returned error
    value, err := k.GetFromEnvOrKms("INVALID_KEY", true)
    // => error
}
```

## ProTip
### Securely embed secret values in `app.yaml` for Google App Engine
```yaml
# app.yaml
runtime: go113

env_variables:
  KMS_ACCESS_TOKEN: "THIS_IS_BASE64_ENCODED_CIPHER_TEXT"
```

## Development
```
cp .envrc .envrc.example
vi .envrc
```
