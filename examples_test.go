package golibsecret_test

import (
	"fmt"
	"log"

	golibsecret "github.com/yourorg/go-libsecret"
)

// Example demonstrates how to define a password schema
func ExampleNewSchema() {
	// Define a schema for storing web passwords
	schema, err := golibsecret.NewSchema(
		"org.example.WebPassword",
		golibsecret.SchemaFlagsNone,
		map[string]golibsecret.SchemaAttributeType{
			"username": golibsecret.SchemaAttributeString,
			"url":      golibsecret.SchemaAttributeString,
			"port":     golibsecret.SchemaAttributeInteger,
			"ssl":      golibsecret.SchemaAttributeBoolean,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	defer schema.Unref()

	fmt.Printf("Schema: %s\n", schema.Name())
	fmt.Printf("Attributes: %v\n", schema.Attributes())
}

// Example demonstrates creating a secret value from text
func ExampleNewValue() {
	// Create a secret value from a password string
	value, err := golibsecret.NewValue("my-secret-password", -1, "text/plain")
	if err != nil {
		log.Fatal(err)
	}
	defer value.Unref()

	// Retrieve the secret as text
	secret, err := value.GetText()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Secret length: %d\n", len(secret))
	// Output: Secret length: 18
}

// Example demonstrates creating a secret value from binary data
func ExampleNewValueFromBytes() {
	// Create a secret value from binary data (e.g., API key)
	apiKey := []byte{0x4b, 0x45, 0x59, 0x31, 0x32, 0x33} // "KEY123"
	value, err := golibsecret.NewValueFromBytes(apiKey, "application/octet-stream")
	if err != nil {
		log.Fatal(err)
	}
	defer value.Unref()

	// Retrieve the secret as bytes
	data, length, err := value.Get()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Secret length: %d bytes\n", length)
	fmt.Printf("First byte: 0x%02x\n", data[0])
	// Output: 
	// Secret length: 6 bytes
	// First byte: 0x4b
}

// Example demonstrates schema attribute types
func ExampleSchemaAttributeType() {
	fmt.Println("String:", golibsecret.SchemaAttributeString)
	fmt.Println("Integer:", golibsecret.SchemaAttributeInteger)
	fmt.Println("Boolean:", golibsecret.SchemaAttributeBoolean)
	// Output:
	// String: STRING
	// Integer: INTEGER
	// Boolean: BOOLEAN
}

// Example demonstrates working with schema flags
func ExampleSchemaFlags() {
	// Create a schema that doesn't match the schema name
	// (useful for migrating from libgnome-keyring)
	schema, err := golibsecret.NewSchema(
		"org.example.LegacyPassword",
		golibsecret.SchemaFlagsDontMatchName,
		map[string]golibsecret.SchemaAttributeType{
			"application": golibsecret.SchemaAttributeString,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	defer schema.Unref()

	fmt.Printf("Flags: %s\n", schema.Flags())
	// Output: Flags: DONT_MATCH_NAME
}

// Example demonstrates complete workflow with schema and value
func Example_completeWorkflow() {
	// Step 1: Define a schema for database credentials
	schema, err := golibsecret.NewSchema(
		"org.example.DatabaseCredentials",
		golibsecret.SchemaFlagsNone,
		map[string]golibsecret.SchemaAttributeType{
			"database": golibsecret.SchemaAttributeString,
			"username": golibsecret.SchemaAttributeString,
			"host":     golibsecret.SchemaAttributeString,
			"port":     golibsecret.SchemaAttributeInteger,
			"useSSL":   golibsecret.SchemaAttributeBoolean,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	defer schema.Unref()

	// Step 2: Create a secret value for the password
	password, err := golibsecret.NewValue("super-secret-db-password", -1, "text/plain")
	if err != nil {
		log.Fatal(err)
	}
	defer password.Unref()

	// Step 3: Work with the schema and value
	fmt.Printf("Schema: %s\n", schema.Name())
	fmt.Printf("Password length: %d bytes\n", password.Len())
	
	contentType, _ := password.GetContentType()
	fmt.Printf("Content type: %s\n", contentType)
	
	// Output:
	// Schema: org.example.DatabaseCredentials
	// Password length: 24 bytes
	// Content type: text/plain
}
