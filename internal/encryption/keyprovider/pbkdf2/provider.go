// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

// Package pbkdf2 contains a key provider that takes a passphrase and emits a PBKDF2 hash of the configured length.
package pbkdf2

import (
	"fmt"
	"github.com/opentofu/opentofu/internal/encryption/keyprovider"
	"hash"
	"io"

	goPBKDF2 "golang.org/x/crypto/pbkdf2"
)

type pbkdf2KeyProvider struct {
	randomSource            io.Reader
	passphrase              string
	iterations              int
	hashFunctionName        HashFunctionName
	hashFunctionProvider    func() hash.Hash
	saltLength              int
	keyLength               int
	decryptSalt             []byte
	decryptIterations       int
	decryptHashFunctionName HashFunctionName
	decryptHashFunction     func() hash.Hash
}

func (p pbkdf2KeyProvider) Provide() ([]byte, []byte, any, error) {
	salt := make([]byte, p.saltLength)
	if _, err := io.ReadFull(p.randomSource, salt); err != nil {
		return nil, nil, nil, &keyprovider.ErrKeyProviderFailure{
			Message: fmt.Sprintf("failed to obtain %d bytes of random data", p.saltLength),
			Cause:   err,
		}
	}
	decryptSalt := p.decryptSalt
	if len(decryptSalt) == 0 {
		decryptSalt = salt
	}
	decryptIterations := p.decryptIterations
	if decryptIterations == 0 {
		decryptIterations = p.iterations
	}

	return goPBKDF2.Key([]byte(p.passphrase), salt, p.iterations, p.keyLength, p.hashFunctionProvider),
		goPBKDF2.Key([]byte(p.passphrase), decryptSalt, decryptIterations, p.keyLength, p.decryptHashFunction),
		Metadata{
			HashFunction: p.hashFunctionName,
			Salt:         fmt.Sprintf("%x", salt),
			Iterations:   p.iterations,
		},
		nil
}
