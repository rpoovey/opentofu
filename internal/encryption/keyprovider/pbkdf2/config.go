// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pbkdf2

import (
	"encoding/hex"
	"fmt"
	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
	"hash"
	"io"
)

// HashFunctionName describes a hash function to use for PBKDF2 hash generation. the hash function influences
type HashFunctionName string

func (h HashFunctionName) Validate() error {
	if h == "" {
		return &keyprovider.ErrInvalidConfiguration{Message: "please specify a hash function"}
	}
	if _, ok := hashFunctions[h]; !ok {
		return &keyprovider.ErrInvalidConfiguration{Message: fmt.Sprintf("invalid hash function name: %s", h)}
	}
	return nil
}

type hashFunction struct {
	functionProvider func() hash.Hash
}

type Config struct {
	randomSource io.Reader

	Passphrase   string           `hcl:"passphrase"`
	KeyLength    int              `hcl:"key_length,optional"`
	Iterations   int              `hcl:"iterations,optional"`
	HashFunction HashFunctionName `hcl:"hash_function,optional"`
	SaltLength   int              `hcl:"salt_length,optional"`

	DecryptSalt         string           `meta:"salt"`
	DecryptIterations   int              `meta:"iterations"`
	DecryptHashFunction HashFunctionName `meta:"hash_function"`
}

func (c Config) Build() (keyprovider.KeyProvider, error) {
	// TODO: validate passphrase length.
	// TODO: validate iterations
	// TODO: validate salt length

	if err := c.HashFunction.Validate(); err != nil {
		return nil, &keyprovider.ErrInvalidConfiguration{
			Cause: err,
		}
	}

	encryptHashFunction := hashFunctions[c.HashFunction]

	var decryptionSalt []byte
	if len(c.DecryptSalt) > 0 {
		var err error
		decryptionSalt, err = hex.DecodeString(c.DecryptSalt)
		if err != nil {
			return nil, &keyprovider.ErrInvalidMetadata{
				Message: "failed to hex-decode stored salt, possible data corruption",
				Cause:   err,
			}
		}
	}

	var decryptHashFunction hashFunction
	var decryptHashFunctionName HashFunctionName
	if c.DecryptHashFunction == "" {
		decryptHashFunction = encryptHashFunction
		decryptHashFunctionName = c.HashFunction
	} else {
		if err := c.DecryptHashFunction.Validate(); err != nil {
			return nil, err
		}
		decryptHashFunction = hashFunctions[c.DecryptHashFunction]
		decryptHashFunctionName = c.DecryptHashFunction
	}

	return &pbkdf2KeyProvider{
		randomSource:            c.randomSource,
		passphrase:              c.Passphrase,
		keyLength:               c.KeyLength,
		iterations:              c.Iterations,
		hashFunctionName:        c.HashFunction,
		hashFunctionProvider:    encryptHashFunction.functionProvider,
		saltLength:              c.SaltLength,
		decryptSalt:             decryptionSalt,
		decryptIterations:       c.DecryptIterations,
		decryptHashFunctionName: decryptHashFunctionName,
		decryptHashFunction:     decryptHashFunction.functionProvider,
	}, nil
}
