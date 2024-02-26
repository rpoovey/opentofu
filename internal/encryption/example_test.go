// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2023 HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package encryption_test

import (
	"fmt"
	"github.com/opentofu/opentofu/internal/encryption/keyprovider/pbkdf2"

	"github.com/hashicorp/hcl/v2"
	"github.com/opentofu/opentofu/internal/encryption"
	"github.com/opentofu/opentofu/internal/encryption/config"
	"github.com/opentofu/opentofu/internal/encryption/method/aesgcm"
	"github.com/opentofu/opentofu/internal/encryption/registry/lockingencryptionregistry"
)

var (
	ConfigA = `
backend {
	enforced = true
}
`
	ConfigB = `
key_provider "static" "basic" {
	key = "6f6f706830656f67686f6834616872756f3751756165686565796f6f72653169"
}
method "aes_gcm" "example" {
	cipher = key_provider.static.basic
}
statefile {
	method = method.aes_gcm.example
}

backend {
	method = method.aes_gcm.example
}
`
)

// This example demonstrates how to use the encryption package to encrypt and decrypt data.
func Example() {
	// Construct a new registry
	// the registry is where we store the key providers and methods
	reg := lockingencryptionregistry.New()
	if err := reg.RegisterKeyProvider(pbkdf2.New()); err != nil {
		panic(err)
	}
	if err := reg.RegisterMethod(aesgcm.New()); err != nil {
		panic(err)
	}

	// Load the 2 different configurations
	cfgA, diags := config.LoadConfigFromString("Test Source A", ConfigA)
	handleDiags(diags)

	cfgB, diags := config.LoadConfigFromString("Test Source B", ConfigB)
	handleDiags(diags)

	// Merge the configurations
	cfg := config.MergeConfigs(cfgA, cfgB)

	// Construct the encryption object
	enc := encryption.New(reg, cfg)

	// Encrypt the data, for this example we will be using the string "test",
	// but in a real world scenario this would be the plan file.
	sourceData := []byte("test")
	encrypted, diags := enc.StateFile().EncryptState(sourceData)
	handleDiags(diags)

	if string(encrypted) == "test" {
		panic("The data has not been encrypted!")
	}

	println(string(encrypted))

	// Decrypt
	decryptedState, err := enc.StateFile().DecryptState(encrypted)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", decryptedState)
	// Output: test
}

func handleDiags(diags hcl.Diagnostics) {
	for _, d := range diags {
		println(d.Error())
	}
	if diags.HasErrors() {
		panic(diags.Error())
	}
}
