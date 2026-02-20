// keyvault-key-reader reads key properties from an Azure Key Vault using
// the armkeyvault SDK. Authentication uses DefaultAzureCredential, which
// supports environment variables, managed identity, az CLI, and more.
//
// Usage:
//
//	go run main.go -subscription <id> -resource-group <rg> -vault <name> [-key <keyname>]
//
// If -key is omitted, all keys in the vault are listed with their properties.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault/v2"
)

func main() {
	subscriptionID := flag.String("subscription", "", "Azure subscription ID (required)")
	resourceGroup := flag.String("resource-group", "", "Resource group name (required)")
	vaultName := flag.String("vault", "", "Key vault name (required)")
	keyName := flag.String("key", "", "Key name (optional; omit to list all keys)")
	flag.Parse()

	if *subscriptionID == "" || *resourceGroup == "" || *vaultName == "" {
		fmt.Fprintln(os.Stderr, "Error: -subscription, -resource-group, and -vault are required")
		flag.Usage()
		os.Exit(1)
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain credential: %v", err)
	}

	clientFactory, err := armkeyvault.NewClientFactory(*subscriptionID, cred, nil)
	if err != nil {
		log.Fatalf("failed to create client factory: %v", err)
	}

	keysClient := clientFactory.NewKeysClient()
	ctx := context.Background()

	if *keyName != "" {
		// Fetch a specific key.
		resp, err := keysClient.Get(ctx, *resourceGroup, *vaultName, *keyName, nil)
		if err != nil {
			log.Fatalf("failed to get key %q: %v", *keyName, err)
		}
		printKey(resp.Key)
	} else {
		// List all keys in the vault.
		fmt.Printf("Keys in vault %q (resource group: %q):\n\n", *vaultName, *resourceGroup)
		pager := keysClient.NewListPager(*resourceGroup, *vaultName, nil)
		count := 0
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				log.Fatalf("failed to list keys: %v", err)
			}
			for _, k := range page.Value {
				count++
				printKey(*k)
			}
		}
		if count == 0 {
			fmt.Println("No keys found.")
		}
	}
}

// printKey prints the properties of a Key resource.
func printKey(k armkeyvault.Key) {
	name := derefStr(k.Name)
	id := derefStr(k.ID)
	location := derefStr(k.Location)

	fmt.Printf("Key: %s\n", name)
	fmt.Printf("  ID:       %s\n", id)
	fmt.Printf("  Location: %s\n", location)

	if p := k.Properties; p != nil {
		if p.Kty != nil {
			fmt.Printf("  Type:     %s\n", *p.Kty)
		}
		if p.KeySize != nil {
			fmt.Printf("  Key Size: %d bits\n", *p.KeySize)
		}
		if p.CurveName != nil {
			fmt.Printf("  Curve:    %s\n", *p.CurveName)
		}
		if len(p.KeyOps) > 0 {
			fmt.Printf("  Key Ops: ")
			for i, op := range p.KeyOps {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%s", *op)
			}
			fmt.Println()
		}
		if p.KeyURI != nil {
			fmt.Printf("  Key URI:  %s\n", *p.KeyURI)
		}
		if p.KeyURIWithVersion != nil {
			fmt.Printf("  Key URI (versioned): %s\n", *p.KeyURIWithVersion)
		}
		if attr := p.Attributes; attr != nil {
			if attr.Enabled != nil {
				fmt.Printf("  Enabled:    %v\n", *attr.Enabled)
			}
			if attr.Exportable != nil {
				fmt.Printf("  Exportable: %v\n", *attr.Exportable)
			}
			if attr.Created != nil {
				fmt.Printf("  Created:    %s\n", time.Unix(*attr.Created, 0).UTC().Format(time.RFC3339))
			}
			if attr.Updated != nil {
				fmt.Printf("  Updated:    %s\n", time.Unix(*attr.Updated, 0).UTC().Format(time.RFC3339))
			}
			if attr.Expires != nil {
				fmt.Printf("  Expires:    %s\n", time.Unix(*attr.Expires, 0).UTC().Format(time.RFC3339))
			}
			if attr.NotBefore != nil {
				fmt.Printf("  Not Before: %s\n", time.Unix(*attr.NotBefore, 0).UTC().Format(time.RFC3339))
			}
		}
		if p.ReleasePolicy != nil {
			fmt.Printf("  Release Policy: configured\n")
		}
		if p.RotationPolicy != nil {
			fmt.Printf("  Rotation Policy: configured\n")
		}
	}

	if len(k.Tags) > 0 {
		fmt.Printf("  Tags:\n")
		for k, v := range k.Tags {
			fmt.Printf("    %s = %s\n", k, derefStr(v))
		}
	}
	fmt.Println()
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
