package golibsecret

/*
#cgo pkg-config: libsecret-1
#include <libsecret/secret.h>
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// Attributes represents a collection of key-value pairs used to identify
// and look up secrets. Attributes are NOT encrypted and should not contain
// sensitive information. They are used like tags to find stored secrets.
//
// Mapped from C type: GHashTable containing string keys and values
type Attributes struct {
	// cAttributes is the underlying C GHashTable pointer
	cAttributes *C.GHashTable
}

// NewAttributes creates a new empty attribute collection.
// Use Set() to add attributes.
//
// Example:
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("username", "john.doe")
//	attrs.Set("url", "https://example.com")
//	defer attrs.Free()
func NewAttributes() *Attributes {
	// Create a GHashTable that owns its keys and values
	hashTable := C.g_hash_table_new_full(
		C.GHashFunc(C.g_str_hash),
		C.GEqualFunc(C.g_str_equal),
		C.GDestroyNotify(C.g_free), // Free key strings
		C.GDestroyNotify(C.g_free), // Free value strings
	)

	attributes := &Attributes{
		cAttributes: hashTable,
	}

	// Set up finalizer to free C memory when Go object is garbage collected
	runtime.SetFinalizer(attributes, (*Attributes).free)

	return attributes
}

// AttributesFromMap creates a new attribute collection from a Go map.
// This is the most convenient way to initialize attributes.
//
// Example:
//
//	attrs, err := golibsecret.AttributesFromMap(map[string]string{
//	    "username": "john.doe",
//	    "url":      "https://example.com",
//	    "port":     "8080", // All values are strings
//	    "ssl":      "true", // Booleans are stored as "true" or "false"
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer attrs.Free()
func AttributesFromMap(values map[string]string) (*Attributes, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("attributes map cannot be empty")
	}

	attrs := NewAttributes()

	for key, value := range values {
		if key == "" {
			attrs.free()
			return nil, fmt.Errorf("attribute key cannot be empty")
		}
		if value == "" {
			// Allow empty values but warn about it
			continue
		}

		if err := attrs.set(key, value); err != nil {
			attrs.free()
			return nil, fmt.Errorf("failed to set attribute %q: %w", key, err)
		}
	}

	return attrs, nil
}

// Set adds or updates an attribute. All attribute values are stored as strings.
// For boolean values, use "true" or "false".
// For integer values, use decimal string representation.
//
// Example:
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("username", "john.doe")
//	attrs.Set("port", "8080")     // Integer stored as string
//	attrs.Set("ssl", "true")      // Boolean stored as string
//	defer attrs.Free()
func (a *Attributes) Set(key, value string) error {
	return a.set(key, value)
}

// set is the internal method that actually sets the attribute
func (a *Attributes) set(key, value string) error {
	if a.cAttributes == nil {
		return fmt.Errorf("attributes is nil")
	}

	if key == "" {
		return fmt.Errorf("attribute key cannot be empty")
	}

	cKey := C.CString(key)
	cValue := C.CString(value)

	C.g_hash_table_insert(
		a.cAttributes,
		C.gpointer(cKey),
		C.gpointer(cValue),
	)

	return nil
}

// Get retrieves an attribute value by key.
// Returns empty string if the key doesn't exist.
//
// Example:
//
//	username := attrs.Get("username")
//	if username == "" {
//	    log.Println("username not found")
//	}
func (a *Attributes) Get(key string) string {
	if a.cAttributes == nil {
		return ""
	}

	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	cValue := C.g_hash_table_lookup(a.cAttributes, C.gconstpointer(cKey))
	if cValue == nil {
		return ""
	}

	return C.GoString((*C.gchar)(cValue))
}

// Has checks if an attribute key exists.
//
// Example:
//
//	if attrs.Has("ssl") {
//	    fmt.Println("SSL setting found")
//	}
func (a *Attributes) Has(key string) bool {
	if a.cAttributes == nil {
		return false
	}

	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	return C.g_hash_table_contains(a.cAttributes, C.gconstpointer(cKey)) != 0
}

// Delete removes an attribute by key.
// Returns true if the key existed and was removed.
//
// Example:
//
//	removed := attrs.Delete("ssl")
//	if removed {
//	    fmt.Println("SSL attribute removed")
//	}
func (a *Attributes) Delete(key string) bool {
	if a.cAttributes == nil {
		return false
	}

	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	return C.g_hash_table_remove(a.cAttributes, C.gconstpointer(cKey)) != 0
}

// Keys returns all attribute keys as a slice.
//
// Example:
//
//	for _, key := range attrs.Keys() {
//	    value := attrs.Get(key)
//	    fmt.Printf("%s: %s\n", key, value)
//	}
func (a *Attributes) Keys() []string {
	if a.cAttributes == nil {
		return nil
	}

	keys := make([]string, 0)

	// Create a GHashTableIter for iteration
	var iter C.GHashTableIter
	C.g_hash_table_iter_init(&iter, a.cAttributes)

	var key, value C.gpointer
	var cKeyString *C.gchar

	// Iterate through the hash table
	for C.g_hash_table_iter_next(&iter, &key, &value) != 0 {
		if key != nil {
			cKeyString = (*C.gchar)(key)
			keys = append(keys, C.GoString(cKeyString))
		}
	}

	return keys
}

// Len returns the number of attributes.
//
// Example:
//
//	count := attrs.Len()
//	fmt.Printf("Attributes count: %d\n", count)
func (a *Attributes) Len() int {
	if a.cAttributes == nil {
		return 0
	}

	return int(C.g_hash_table_size(a.cAttributes))
}

// IsEmpty returns true if the attribute collection is empty.
//
// Example:
//
//	if attrs.IsEmpty() {
//	    log.Println("No attributes set")
//	}
func (a *Attributes) IsEmpty() bool {
	return a.Len() == 0
}

// ToMap returns all attributes as a Go map.
// This creates a copy of the attribute data.
//
// Example:
//
//	attrMap := attrs.ToMap()
//	for key, value := range attrMap {
//	    fmt.Printf("%s: %s\n", key, value)
//	}
func (a *Attributes) ToMap() map[string]string {
	if a.cAttributes == nil {
		return nil
	}

	result := make(map[string]string)
	var iter C.GHashTableIter
	C.g_hash_table_iter_init(&iter, a.cAttributes)

	var key, value C.gpointer
	var cKeyString, cValueString *C.gchar

	for C.g_hash_table_iter_next(&iter, &key, &value) != 0 {
		if key != nil && value != nil {
			cKeyString = (*C.gchar)(key)
			cValueString = (*C.gchar)(value)
			result[C.GoString(cKeyString)] = C.GoString(cValueString)
		}
	}

	return result
}

// Free releases the underlying C resources for the attributes.
// This should be called when you're done with the attributes
// to avoid memory leaks. After calling Free(), the Attributes
// object should not be used.
//
// Example:
//
//	attrs := golibsecret.NewAttributes()
//	defer attrs.Free()
func (a *Attributes) free() {
	if a.cAttributes != nil {
		C.g_hash_table_unref(a.cAttributes)
		a.cAttributes = nil
	}
}

// Free releases the underlying C resources for the attributes.
// This is an alias for free() for clarity.
//
// Example:
//
//	attrs := golibsecret.NewAttributes()
//	defer attrs.Free()
func (a *Attributes) Free() {
	a.free()
}

// GetGHashTable returns the underlying C GHashTable pointer.
// This is used internally by other libsecret functions.
//
// Warning: This gives direct access to the C hash table.
// Only use this if you know what you're doing.
func (a *Attributes) GetGHashTable() *C.GHashTable {
	return a.cAttributes
}

// String returns a string representation of the attributes for debugging.
// Note: This does NOT expose the actual attribute values for security reasons.
func (a *Attributes) String() string {
	if a.cAttributes == nil {
		return "Attributes{nil}"
	}

	return fmt.Sprintf("Attributes{count=%d, keys=%v}",
		a.Len(), a.Keys())
}

// Equals compares two Attributes objects for equality based on their content.
func (a *Attributes) Equals(other *Attributes) bool {
	if a == nil || other == nil {
		return a == other
	}

	if a.Len() != other.Len() {
		return false
	}

	// Check if all keys exist and have same values
	for _, key := range a.Keys() {
		if !other.Has(key) {
			return false
		}
		if a.Get(key) != other.Get(key) {
			return false
		}
	}

	return true
}

// Validate checks if attributes are valid according to the provided schema.
// This is a direct binding to the C secret_attributes_validate function.
//
// It verifies:
//   - Schema name consistency (if xdg:schema attribute is present)
//   - Attribute names are defined in the schema
//   - Attribute values can be parsed according to their schema types
//
// Returns nil if validation succeeds, or an error with details about what failed.
//
// Example:
//
//	schema, _ := golibsecret.NewSchema("org.example.Password", golibsecret.SchemaFlagsNone, map[string]golibsecret.SchemaAttributeType{
//	    "username": golibsecret.SchemaAttributeString,
//	    "port":     golibsecret.SchemaAttributeInteger,
//	    "ssl":      golibsecret.SchemaAttributeBoolean,
//	})
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("username", "john")
//	attrs.Set("port", "8080")
//	attrs.Set("ssl", "true")
//
//	if err := attrs.Validate(schema); err != nil {
//	    log.Fatal("Invalid attributes:", err)
//	}
func (a *Attributes) Validate(schema *Schema) error {
	if a.cAttributes == nil {
		return fmt.Errorf("attributes is nil")
	}

	if schema == nil || schema.cSchema == nil {
		return fmt.Errorf("schema is nil")
	}

	var cError *C.GError

	result := C.secret_attributes_validate(
		schema.cSchema,
		a.cAttributes,
		&cError,
	)

	if result == 0 {
		// Validation failed
		if cError != nil {
			errMsg := C.GoString(cError.message)
			C.g_error_free(cError)
			return fmt.Errorf("attribute validation failed: %s", errMsg)
		}
		return fmt.Errorf("attribute validation failed")
	}

	return nil
}

// ValidateAttributes validates that a set of attributes conforms to the given schema
// using the underlying C secret_attributes_validate function.
//
// This is a convenience function that wraps Attributes.Validate().
//
// It verifies:
//   - Schema name consistency (if xdg:schema attribute is present)
//   - Attribute names are defined in the schema
//   - Attribute values can be parsed according to their schema types
//
// Returns nil if validation succeeds, or an error with details about what failed.
//
// Example:
//
//	err := golibsecret.ValidateAttributes(schema, attrs)
//	if err != nil {
//	    log.Fatal("Invalid attributes:", err)
//	}
func ValidateAttributes(schema *Schema, attrs *Attributes) error {
	if schema == nil {
		return fmt.Errorf("schema cannot be nil")
	}
	if attrs == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	return attrs.Validate(schema)
}

// Clone creates a copy of the attributes collection.
// The returned copy can be modified independently.
//
// Example:
//
//	original := golibsecret.NewAttributes()
//	original.Set("key", "value")
//
//	clone := original.Clone()
//	clone.Set("new_key", "new_value")
//
//	fmt.Println("Original count:", original.Len())
//	fmt.Println("Clone count:", clone.Len())
func (a *Attributes) Clone() (*Attributes, error) {
	if a.cAttributes == nil {
		return nil, fmt.Errorf("attributes is nil")
	}

	// Create new attributes and copy all key-value pairs
	clone := NewAttributes()
	var iter C.GHashTableIter
	C.g_hash_table_iter_init(&iter, a.cAttributes)

	var key, value C.gpointer
	var cKeyString, cValueString *C.gchar

	for C.g_hash_table_iter_next(&iter, &key, &value) != 0 {
		if key != nil && value != nil {
			cKeyString = (*C.gchar)(key)
			cValueString = (*C.gchar)(value)

			cKey := C.CString(C.GoString(cKeyString))
			cValue := C.CString(C.GoString(cValueString))

			C.g_hash_table_insert(clone.cAttributes, C.gpointer(cKey), C.gpointer(cValue))
		}
	}

	return clone, nil
}
