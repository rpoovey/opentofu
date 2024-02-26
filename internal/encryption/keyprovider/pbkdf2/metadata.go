// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pbkdf2

// Metadata describes the metadata to be stored alongside the encrypted form.
type Metadata struct {
	Salt         string           `meta:"salt"`
	Iterations   int              `meta:"iterations"`
	HashFunction HashFunctionName `meta:"hash_function"`
}
