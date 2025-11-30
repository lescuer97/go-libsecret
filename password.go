package golibsecret

/*
#cgo pkg-config: libsecret-1
#include <libsecret/secret.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
)

// PasswordLookupSync looks up a password in the secret service synchronously.
//
// This is a direct binding to the C secret_password_lookupv_sync function.
// It searches for a stored password that matches the given schema and attributes.
//
// Parameters:
//   - schema: The schema that defines the expected attribute types. Can be nil
//     to match any schema.
//   - attributes: Key-value pairs used to identify the secret. These must match
//     the attributes used when the password was stored.
//
// Returns:
//   - The password string if found
//   - Empty string and nil error if no matching password was found
//   - Empty string and error if an error occurred
//
// Note: This method blocks until the operation completes. Do not use in
// UI threads or performance-critical code paths.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.Password", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "username": golibsecret.SchemaAttributeString,
//	    "service":  golibsecret.SchemaAttributeString,
//	})
//	defer schema.Unref()
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("username", "john.doe")
//	attrs.Set("service", "myapp")
//	defer attrs.Free()
//
//	password, err := golibsecret.PasswordLookupSync(schema, attrs)
//	if err != nil {
//	    log.Fatal("Lookup failed:", err)
//	}
//	if password == "" {
//	    fmt.Println("No password found")
//	} else {
//	    fmt.Println("Password found")
//	    // Use the password...
//	}
func PasswordLookupSync(schema *Schema, attributes *Attributes) (string, error) {
	if attributes == nil || attributes.cAttributes == nil {
		return "", fmt.Errorf("attributes cannot be nil")
	}

	var cSchema *C.SecretSchema
	if schema != nil {
		cSchema = schema.cSchema
	}

	var cError *C.GError

	// Call the C function
	// Note: cancellable is NULL for simple synchronous usage
	cPassword := C.secret_password_lookupv_sync(
		cSchema,
		attributes.cAttributes,
		nil, // GCancellable - NULL for synchronous operation
		&cError,
	)

	// Check for errors
	if cError != nil {
		errMsg := C.GoString(cError.message)
		C.g_error_free(cError)
		return "", fmt.Errorf("password lookup failed: %s", errMsg)
	}

	// No password found (not an error, just not found)
	if cPassword == nil {
		return "", nil
	}

	// Convert to Go string
	password := C.GoString(cPassword)

	// Free the C password string using secret_password_free
	C.secret_password_free(cPassword)

	return password, nil
}

// PasswordLookup is an alias for PasswordLookupSync for convenience.
// See PasswordLookupSync for full documentation.
func PasswordLookup(schema *Schema, attributes *Attributes) (string, error) {
	return PasswordLookupSync(schema, attributes)
}

// LookupPassword looks up a password using a map of attributes.
// This is a convenience function that creates Attributes from the map internally.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.Password", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "username": golibsecret.SchemaAttributeString,
//	})
//
//	password, err := golibsecret.LookupPassword(schema, map[string]string{
//	    "username": "john.doe",
//	})
func LookupPassword(schema *Schema, attributeMap map[string]string) (string, error) {
	if len(attributeMap) == 0 {
		return "", fmt.Errorf("attributes map cannot be empty")
	}

	attrs, err := AttributesFromMap(attributeMap)
	if err != nil {
		return "", fmt.Errorf("failed to create attributes: %w", err)
	}
	defer attrs.Free()

	return PasswordLookupSync(schema, attrs)
}

