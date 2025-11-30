package golibsecret

/*
#cgo pkg-config: libsecret-1
#include <libsecret/secret.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Collection aliases for storing passwords
const (
	// CollectionDefault is an alias to the default collection.
	// This collection is stored on disk and persists across login sessions.
	CollectionDefault = "default"

	// CollectionSession is an alias to the session collection.
	// This collection is stored in memory and will be cleared when
	// the user ends their session (logs out or restarts).
	CollectionSession = "session"
)

// SearchFlags control behavior of password search operations.
//
// Mapped from C enum: SecretSearchFlags
type SearchFlags int

const (
	// SearchFlagsNone indicates no special search flags.
	// Only the first matching item will be returned.
	SearchFlagsNone SearchFlags = C.SECRET_SEARCH_NONE

	// SearchFlagsAll returns all items matching the search, instead of just the first one.
	SearchFlagsAll SearchFlags = C.SECRET_SEARCH_ALL

	// SearchFlagsUnlock will unlock locked items while searching.
	// Locked and unlocked items will match the search and be returned.
	// If the unlock fails, the search does not fail.
	SearchFlagsUnlock SearchFlags = C.SECRET_SEARCH_UNLOCK

	// SearchFlagsLoadSecrets will load secret values for items that are not locked.
	// The secrets can then be retrieved via SearchResult.RetrieveSecret().
	SearchFlagsLoadSecrets SearchFlags = C.SECRET_SEARCH_LOAD_SECRETS
)

// String returns the string representation of SearchFlags
func (f SearchFlags) String() string {
	switch f {
	case SearchFlagsNone:
		return "NONE"
	case SearchFlagsAll:
		return "ALL"
	case SearchFlagsUnlock:
		return "UNLOCK"
	case SearchFlagsLoadSecrets:
		return "LOAD_SECRETS"
	default:
		return fmt.Sprintf("FLAGS(%d)", f)
	}
}

// SearchResult represents a single item found during a password search.
// It provides access to the item's attributes, label, and timestamps,
// as well as the ability to retrieve the secret value.
type SearchResult struct {
	// cRetrievable is the underlying C SecretRetrievable pointer
	cRetrievable *C.SecretRetrievable
}

// GetAttributes returns the attributes of the search result item.
// These are the key-value pairs used to identify the secret.
func (r *SearchResult) GetAttributes() map[string]string {
	if r.cRetrievable == nil {
		return nil
	}

	cAttrs := C.secret_retrievable_get_attributes(r.cRetrievable)
	if cAttrs == nil {
		return nil
	}
	defer C.g_hash_table_unref(cAttrs)

	result := make(map[string]string)
	var iter C.GHashTableIter
	C.g_hash_table_iter_init(&iter, cAttrs)

	var key, value C.gpointer
	for C.g_hash_table_iter_next(&iter, &key, &value) != 0 {
		if key != nil && value != nil {
			cKey := (*C.gchar)(key)
			cValue := (*C.gchar)(value)
			result[C.GoString(cKey)] = C.GoString(cValue)
		}
	}

	return result
}

// GetLabel returns the human-readable label of the search result item.
func (r *SearchResult) GetLabel() string {
	if r.cRetrievable == nil {
		return ""
	}

	cLabel := C.secret_retrievable_get_label(r.cRetrievable)
	if cLabel == nil {
		return ""
	}
	defer C.g_free(C.gpointer(cLabel))

	return C.GoString(cLabel)
}

// GetCreated returns the Unix timestamp when the item was created.
func (r *SearchResult) GetCreated() uint64 {
	if r.cRetrievable == nil {
		return 0
	}
	return uint64(C.secret_retrievable_get_created(r.cRetrievable))
}

// GetModified returns the Unix timestamp when the item was last modified.
func (r *SearchResult) GetModified() uint64 {
	if r.cRetrievable == nil {
		return 0
	}
	return uint64(C.secret_retrievable_get_modified(r.cRetrievable))
}

// RetrieveSecret retrieves the secret value synchronously.
// This may require unlocking the item if it's locked.
//
// Returns the secret Value, or nil if retrieval failed.
// The caller is responsible for calling Unref() on the returned Value.
func (r *SearchResult) RetrieveSecret() (*Value, error) {
	if r.cRetrievable == nil {
		return nil, fmt.Errorf("search result is nil")
	}

	var cError *C.GError
	cValue := C.secret_retrievable_retrieve_secret_sync(
		r.cRetrievable,
		nil, // GCancellable
		&cError,
	)

	if cError != nil {
		errMsg := C.GoString(cError.message)
		C.g_error_free(cError)
		return nil, fmt.Errorf("failed to retrieve secret: %s", errMsg)
	}

	if cValue == nil {
		return nil, nil
	}

	return &Value{cValue: cValue}, nil
}

// Free releases the underlying C resources for the search result.
func (r *SearchResult) Free() {
	if r.cRetrievable != nil {
		C.g_object_unref(C.gpointer(r.cRetrievable))
		r.cRetrievable = nil
	}
}

// String returns a string representation of the search result for debugging.
func (r *SearchResult) String() string {
	if r.cRetrievable == nil {
		return "SearchResult{nil}"
	}
	return fmt.Sprintf("SearchResult{label=%q, created=%d, modified=%d}",
		r.GetLabel(), r.GetCreated(), r.GetModified())
}

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

// PasswordStoreSync stores a password in the secret service synchronously.
//
// This is a direct binding to the C secret_password_storev_sync function.
// It stores a password with the given schema, attributes, and label.
//
// Parameters:
//   - schema: The schema that defines the expected attribute types. Can be nil.
//   - attributes: Key-value pairs used to identify and lookup the secret later.
//   - collection: The collection to store the password in. Use CollectionDefault
//     for the default persistent collection, CollectionSession for memory-only
//     storage, or nil/empty string for the default collection.
//   - label: A human-readable label for the password (shown in keyring managers).
//   - password: The password string to store.
//
// If the attributes match a secret item already stored in the collection, then
// the item will be updated with the new password.
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
//	err := golibsecret.PasswordStoreSync(schema, attrs, golibsecret.CollectionDefault, "MyApp Password", "secret123")
//	if err != nil {
//	    log.Fatal("Store failed:", err)
//	}
func PasswordStoreSync(schema *Schema, attributes *Attributes, collection, label, password string) error {
	if attributes == nil || attributes.cAttributes == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	if label == "" {
		return fmt.Errorf("label cannot be empty")
	}

	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	var cSchema *C.SecretSchema
	if schema != nil {
		cSchema = schema.cSchema
	}

	var cCollection *C.gchar
	if collection != "" {
		cCollection = C.CString(collection)
		defer C.free(unsafe.Pointer(cCollection))
	}

	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	cPassword := C.CString(password)
	defer C.free(unsafe.Pointer(cPassword))

	var cError *C.GError

	// Call the C function
	result := C.secret_password_storev_sync(
		cSchema,
		attributes.cAttributes,
		cCollection,
		cLabel,
		cPassword,
		nil, // GCancellable - NULL for synchronous operation
		&cError,
	)

	// Check for errors
	if cError != nil {
		errMsg := C.GoString(cError.message)
		C.g_error_free(cError)
		return fmt.Errorf("password store failed: %s", errMsg)
	}

	if result == 0 {
		return fmt.Errorf("password store failed")
	}

	return nil
}

// PasswordStore is an alias for PasswordStoreSync for convenience.
// See PasswordStoreSync for full documentation.
func PasswordStore(schema *Schema, attributes *Attributes, collection, label, password string) error {
	return PasswordStoreSync(schema, attributes, collection, label, password)
}

// StorePassword stores a password using a map of attributes.
// This is a convenience function that creates Attributes from the map internally.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.Password", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "username": golibsecret.SchemaAttributeString,
//	})
//
//	err := golibsecret.StorePassword(schema, map[string]string{
//	    "username": "john.doe",
//	}, golibsecret.CollectionDefault, "MyApp Password", "secret123")
func StorePassword(schema *Schema, attributeMap map[string]string, collection, label, password string) error {
	if len(attributeMap) == 0 {
		return fmt.Errorf("attributes map cannot be empty")
	}

	attrs, err := AttributesFromMap(attributeMap)
	if err != nil {
		return fmt.Errorf("failed to create attributes: %w", err)
	}
	defer attrs.Free()

	return PasswordStoreSync(schema, attrs, collection, label, password)
}

// PasswordStoreBinarySync stores a binary secret value in the secret service synchronously.
//
// This is a direct binding to the C secret_password_storev_binary_sync function.
// It stores a SecretValue (which can contain binary data) with the given schema,
// attributes, and label.
//
// Parameters:
//   - schema: The schema that defines the expected attribute types. Can be nil.
//   - attributes: Key-value pairs used to identify and lookup the secret later.
//   - collection: The collection to store the secret in. Use CollectionDefault
//     for the default persistent collection, CollectionSession for memory-only
//     storage, or nil/empty string for the default collection.
//   - label: A human-readable label for the secret (shown in keyring managers).
//   - value: The SecretValue to store (can contain binary data).
//
// If the attributes match a secret item already stored in the collection, then
// the item will be updated with the new value.
//
// Note: This method blocks until the operation completes. Do not use in
// UI threads or performance-critical code paths.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.APIKey", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "service": golibsecret.SchemaAttributeString,
//	})
//	defer schema.Unref()
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("service", "myapi")
//	defer attrs.Free()
//
//	// Create a SecretValue from binary data
//	value, _ := golibsecret.NewValueFromBytes([]byte{0x01, 0x02, 0x03}, "application/octet-stream")
//	defer value.Unref()
//
//	err := golibsecret.PasswordStoreBinarySync(schema, attrs, golibsecret.CollectionDefault, "MyAPI Key", value)
//	if err != nil {
//	    log.Fatal("Store failed:", err)
//	}
func PasswordStoreBinarySync(schema *Schema, attributes *Attributes, collection, label string, value *Value) error {
	if attributes == nil || attributes.cAttributes == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	if label == "" {
		return fmt.Errorf("label cannot be empty")
	}

	if value == nil || value.cValue == nil {
		return fmt.Errorf("value cannot be nil")
	}

	var cSchema *C.SecretSchema
	if schema != nil {
		cSchema = schema.cSchema
	}

	var cCollection *C.gchar
	if collection != "" {
		cCollection = C.CString(collection)
		defer C.free(unsafe.Pointer(cCollection))
	}

	cLabel := C.CString(label)
	defer C.free(unsafe.Pointer(cLabel))

	var cError *C.GError

	// Call the C function
	result := C.secret_password_storev_binary_sync(
		cSchema,
		attributes.cAttributes,
		cCollection,
		cLabel,
		value.cValue,
		nil, // GCancellable - NULL for synchronous operation
		&cError,
	)

	// Check for errors
	if cError != nil {
		errMsg := C.GoString(cError.message)
		C.g_error_free(cError)
		return fmt.Errorf("password store binary failed: %s", errMsg)
	}

	if result == 0 {
		return fmt.Errorf("password store binary failed")
	}

	return nil
}

// PasswordStoreBinary is an alias for PasswordStoreBinarySync for convenience.
// See PasswordStoreBinarySync for full documentation.
func PasswordStoreBinary(schema *Schema, attributes *Attributes, collection, label string, value *Value) error {
	return PasswordStoreBinarySync(schema, attributes, collection, label, value)
}

// StoreBinarySecret stores a binary secret using a map of attributes.
// This is a convenience function that creates Attributes from the map internally.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.APIKey", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "service": golibsecret.SchemaAttributeString,
//	})
//
//	value, _ := golibsecret.NewValueFromBytes(apiKeyBytes, "application/octet-stream")
//	defer value.Unref()
//
//	err := golibsecret.StoreBinarySecret(schema, map[string]string{
//	    "service": "myapi",
//	}, golibsecret.CollectionDefault, "MyAPI Key", value)
func StoreBinarySecret(schema *Schema, attributeMap map[string]string, collection, label string, value *Value) error {
	if len(attributeMap) == 0 {
		return fmt.Errorf("attributes map cannot be empty")
	}

	attrs, err := AttributesFromMap(attributeMap)
	if err != nil {
		return fmt.Errorf("failed to create attributes: %w", err)
	}
	defer attrs.Free()

	return PasswordStoreBinarySync(schema, attrs, collection, label, value)
}

// PasswordSearchSync searches for items in the secret service synchronously.
//
// This is a direct binding to the C secret_password_searchv_sync function.
// It searches for stored secrets that match the given schema and attributes.
//
// Parameters:
//   - schema: The schema that defines the expected attribute types. Can be nil
//     to match any schema.
//   - attributes: Key-value pairs used to filter the search. Secrets with
//     matching attributes will be returned.
//   - flags: Search options that control behavior:
//   - SearchFlagsNone: Return only the first match
//   - SearchFlagsAll: Return all matching items
//   - SearchFlagsUnlock: Unlock locked items during search
//   - SearchFlagsLoadSecrets: Pre-load secret values for unlocked items
//
// Returns:
//   - A slice of SearchResult items (may be empty if no matches found)
//   - Error if the search operation failed
//
// The caller is responsible for calling Free() on each SearchResult when done.
//
// Note: This method blocks until the operation completes. Do not use in
// UI threads or performance-critical code paths.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.Password", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "service": golibsecret.SchemaAttributeString,
//	})
//	defer schema.Unref()
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("service", "myapp")
//	defer attrs.Free()
//
//	results, err := golibsecret.PasswordSearchSync(schema, attrs, golibsecret.SearchFlagsAll)
//	if err != nil {
//	    log.Fatal("Search failed:", err)
//	}
//
//	for _, result := range results {
//	    fmt.Printf("Found: %s\n", result.GetLabel())
//	    fmt.Printf("Attributes: %v\n", result.GetAttributes())
//
//	    // Retrieve the actual secret
//	    secret, err := result.RetrieveSecret()
//	    if err == nil && secret != nil {
//	        text, _ := secret.GetText()
//	        fmt.Printf("Secret: %s\n", text)
//	        secret.Unref()
//	    }
//
//	    result.Free()
//	}
func PasswordSearchSync(schema *Schema, attributes *Attributes, flags SearchFlags) ([]*SearchResult, error) {
	if attributes == nil || attributes.cAttributes == nil {
		return nil, fmt.Errorf("attributes cannot be nil")
	}

	var cSchema *C.SecretSchema
	if schema != nil {
		cSchema = schema.cSchema
	}

	var cError *C.GError

	// Call the C function
	cList := C.secret_password_searchv_sync(
		cSchema,
		attributes.cAttributes,
		C.SecretSearchFlags(flags),
		nil, // GCancellable - NULL for synchronous operation
		&cError,
	)

	// Check for errors
	if cError != nil {
		errMsg := C.GoString(cError.message)
		C.g_error_free(cError)
		return nil, fmt.Errorf("password search failed: %s", errMsg)
	}

	// Convert GList to Go slice
	var results []*SearchResult

	// Iterate through the GList
	for l := cList; l != nil; l = l.next {
		cRetrievable := (*C.SecretRetrievable)(l.data)
		if cRetrievable != nil {
			// Ref the object since we're taking ownership
			C.g_object_ref(C.gpointer(cRetrievable))
			results = append(results, &SearchResult{
				cRetrievable: cRetrievable,
			})
		}
	}

	// Free the GList (but not the data, since we've taken ownership)
	if cList != nil {
		C.g_list_free(cList)
	}

	return results, nil
}

// PasswordSearch is an alias for PasswordSearchSync for convenience.
// See PasswordSearchSync for full documentation.
func PasswordSearch(schema *Schema, attributes *Attributes, flags SearchFlags) ([]*SearchResult, error) {
	return PasswordSearchSync(schema, attributes, flags)
}

// SearchPasswords searches for passwords using a map of attributes.
// This is a convenience function that creates Attributes from the map internally.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.Password", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "service": golibsecret.SchemaAttributeString,
//	})
//
//	results, err := golibsecret.SearchPasswords(schema, map[string]string{
//	    "service": "myapp",
//	}, golibsecret.SearchFlagsAll)
//
//	for _, result := range results {
//	    fmt.Printf("Found: %s\n", result.GetLabel())
//	    result.Free()
//	}
func SearchPasswords(schema *Schema, attributeMap map[string]string, flags SearchFlags) ([]*SearchResult, error) {
	if len(attributeMap) == 0 {
		return nil, fmt.Errorf("attributes map cannot be empty")
	}

	attrs, err := AttributesFromMap(attributeMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create attributes: %w", err)
	}
	defer attrs.Free()

	return PasswordSearchSync(schema, attrs, flags)
}
