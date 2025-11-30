package golibsecret

/*
#cgo pkg-config: libsecret-1
#include <libsecret/secret.h>
#include <stdlib.h>

// secret_get_schema is defined in secret-schemas.h which is included via secret.h
// but we need to ensure the enum is available
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// SchemaAttributeType defines the type of an attribute in a schema.
// Attributes are used to identify and lookup secrets, but are not encrypted.
//
// Mapped from C enum: SecretSchemaAttributeType
type SchemaAttributeType int

const (
	// SchemaAttributeString represents a string attribute
	SchemaAttributeString SchemaAttributeType = C.SECRET_SCHEMA_ATTRIBUTE_STRING

	// SchemaAttributeInteger represents an integer attribute
	SchemaAttributeInteger SchemaAttributeType = C.SECRET_SCHEMA_ATTRIBUTE_INTEGER

	// SchemaAttributeBoolean represents a boolean attribute
	SchemaAttributeBoolean SchemaAttributeType = C.SECRET_SCHEMA_ATTRIBUTE_BOOLEAN
)

// String returns the string representation of the SchemaAttributeType
func (t SchemaAttributeType) String() string {
	switch t {
	case SchemaAttributeString:
		return "STRING"
	case SchemaAttributeInteger:
		return "INTEGER"
	case SchemaAttributeBoolean:
		return "BOOLEAN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// SchemaAttribute represents a single attribute definition in a schema.
// Each attribute has a name and a type (string, integer, or boolean).
//
// Mapped from C struct: SecretSchemaAttribute
type SchemaAttribute struct {
	Name string
	Type SchemaAttributeType
}

// SchemaFlags defines flags that control schema behavior.
//
// Mapped from C enum: SecretSchemaFlags
type SchemaFlags int

const (
	// SchemaFlagsNone indicates no special flags
	SchemaFlagsNone SchemaFlags = C.SECRET_SCHEMA_NONE

	// SchemaFlagsDontMatchName indicates that the schema name should not be matched
	// when looking up items. This is useful when migrating from libgnome-keyring
	// which didn't store schema names.
	SchemaFlagsDontMatchName SchemaFlags = C.SECRET_SCHEMA_DONT_MATCH_NAME
)

// SchemaType represents predefined schema types available through GetSchema.
//
// Mapped from C enum: SecretSchemaType
type SchemaType int

const (
	// SchemaTypeNote is a predefined schema for personal passwords/notes stored
	// by the user in the password manager. This schema has no attributes, and
	// the items are not meant to be used automatically by applications.
	//
	// Schema name: "org.gnome.keyring.Note"
	SchemaTypeNote SchemaType = C.SECRET_SCHEMA_TYPE_NOTE

	// SchemaTypeCompatNetwork is a predefined schema compatible with items stored
	// via the libgnome-keyring 'network password' functions. This is meant to be
	// used by applications migrating from libgnome-keyring which stored their
	// secrets as 'network passwords'. It is not recommended for new code.
	//
	// Schema name: "org.gnome.keyring.NetworkPassword"
	//
	// Attributes:
	//   - user: The user name (string)
	//   - domain: The login domain or realm (string)
	//   - object: The object or path (string)
	//   - protocol: The protocol (string like 'http')
	//   - port: The network port (integer)
	//   - server: The hostname or server (string)
	//   - authtype: The authentication type (string)
	SchemaTypeCompatNetwork SchemaType = C.SECRET_SCHEMA_TYPE_COMPAT_NETWORK
)

// String returns the string representation of SchemaType
func (t SchemaType) String() string {
	switch t {
	case SchemaTypeNote:
		return "NOTE"
	case SchemaTypeCompatNetwork:
		return "COMPAT_NETWORK"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// String returns the string representation of SchemaFlags
func (f SchemaFlags) String() string {
	switch f {
	case SchemaFlagsNone:
		return "NONE"
	case SchemaFlagsDontMatchName:
		return "DONT_MATCH_NAME"
	default:
		return fmt.Sprintf("FLAGS(%d)", f)
	}
}

// Schema defines the structure of secret items and their attributes.
// Each schema has a name (typically a dotted string like "org.example.Password")
// and a set of attribute definitions that describe what attributes items can have.
//
// Schemas are used to validate attributes when storing and retrieving secrets,
// and the schema name is stored with each item to ensure type safety.
//
// Mapped from C struct: SecretSchema
type Schema struct {
	// cSchema is the underlying C SecretSchema pointer
	cSchema *C.SecretSchema

	// borrowed indicates if this schema is a predefined/static schema
	// that should not be freed (e.g., from GetSchema)
	borrowed bool
}

// NewSchema creates a new schema with the given name, flags, and attributes.
// The schema name should be a dotted string (e.g., "org.example.Password").
//
// The attributes map defines the allowed attributes for items using this schema.
// Each key is the attribute name, and the value is the attribute type.
//
// Example:
//
//	schema, err := NewSchema("org.example.Password", SchemaFlagsNone, map[string]SchemaAttributeType{
//	    "username": SchemaAttributeString,
//	    "port":     SchemaAttributeInteger,
//	    "ssl":      SchemaAttributeBoolean,
//	})
func NewSchema(name string, flags SchemaFlags, attributes map[string]SchemaAttributeType) (*Schema, error) {
	if name == "" {
		return nil, fmt.Errorf("schema name cannot be empty")
	}

	if len(attributes) == 0 {
		return nil, fmt.Errorf("schema must have at least one attribute")
	}

	if len(attributes) > 32 {
		return nil, fmt.Errorf("schema cannot have more than 32 attributes (got %d)", len(attributes))
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	// Create a GHashTable for attributes
	// GHashTable takes ownership of the strings we pass to it
	hashTable := C.g_hash_table_new(nil, nil)
	defer C.g_hash_table_unref(hashTable)

	for attrName, attrType := range attributes {
		cAttrName := C.CString(attrName)
		// Note: g_hash_table_insert takes ownership in some cases
		// We need to be careful with memory management here
		C.g_hash_table_insert(
			hashTable,
			C.gpointer(cAttrName),
			C.gpointer(uintptr(attrType)),
		)
	}

	// Create the schema using secret_schema_newv
	cSchema := C.secret_schema_newv(cName, C.SecretSchemaFlags(flags), hashTable)
	if cSchema == nil {
		return nil, fmt.Errorf("failed to create schema")
	}

	schema := &Schema{
		cSchema: cSchema,
	}

	// Set up finalizer to free C memory when Go object is garbage collected
	runtime.SetFinalizer(schema, (*Schema).free)

	return schema, nil
}

// Name returns the schema's name
func (s *Schema) Name() string {
	if s.cSchema == nil {
		return ""
	}
	return C.GoString(s.cSchema.name)
}

// Flags returns the schema's flags
func (s *Schema) Flags() SchemaFlags {
	if s.cSchema == nil {
		return SchemaFlagsNone
	}
	return SchemaFlags(s.cSchema.flags)
}

// Attributes returns a map of attribute names to their types
func (s *Schema) Attributes() map[string]SchemaAttributeType {
	if s.cSchema == nil {
		return nil
	}

	attrs := make(map[string]SchemaAttributeType)
	
	// Iterate through the C array of attributes (max 32)
	for i := 0; i < 32; i++ {
		attr := s.cSchema.attributes[i]
		if attr.name == nil {
			break // End of attributes (NULL-terminated)
		}
		name := C.GoString(attr.name)
		attrs[name] = SchemaAttributeType(attr._type)
	}

	return attrs
}

// Ref increments the reference count on the schema
func (s *Schema) Ref() *Schema {
	if s.cSchema == nil {
		return nil
	}
	C.secret_schema_ref(s.cSchema)
	return s
}

// Unref decrements the reference count on the schema.
// When the reference count reaches zero, the schema is freed.
//
// Note: Predefined schemas obtained via GetSchema() are static and
// calling Unref() on them is a no-op.
func (s *Schema) Unref() {
	if s.cSchema != nil && !s.borrowed {
		C.secret_schema_unref(s.cSchema)
		s.cSchema = nil
	}
}

// free is called by the finalizer to clean up C resources
func (s *Schema) free() {
	s.Unref()
	s.cSchema = nil
}

// IsBorrowed returns true if this is a predefined schema that should not be freed.
// Predefined schemas are obtained via GetSchema() and are static.
func (s *Schema) IsBorrowed() bool {
	return s.borrowed
}

// String returns a string representation of the schema
func (s *Schema) String() string {
	if s.cSchema == nil {
		return "Schema{nil}"
	}
	borrowed := ""
	if s.borrowed {
		borrowed = ", borrowed=true"
	}
	return fmt.Sprintf("Schema{name=%q, flags=%s, attributes=%d%s}",
		s.Name(), s.Flags(), len(s.Attributes()), borrowed)
}

// GetSchema returns a predefined schema of the given type.
//
// This is a direct binding to the C secret_get_schema function.
// The returned schema is a static/borrowed reference and should NOT be
// freed - calling Unref() on it is safe but has no effect.
//
// Available schema types:
//   - SchemaTypeNote: For personal passwords/notes (no attributes)
//   - SchemaTypeCompatNetwork: For network passwords (libgnome-keyring compatible)
//
// Example:
//
//	// Get the network password schema for migrating from libgnome-keyring
//	schema := golibsecret.GetSchema(golibsecret.SchemaTypeCompatNetwork)
//	// No need to call schema.Unref() - it's a predefined schema
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("user", "john")
//	attrs.Set("server", "example.com")
//	attrs.Set("protocol", "https")
//	defer attrs.Free()
//
//	password, err := golibsecret.PasswordLookupSync(schema, attrs)
func GetSchema(schemaType SchemaType) *Schema {
	cSchema := C.secret_get_schema(C.SecretSchemaType(schemaType))
	if cSchema == nil {
		return nil
	}

	// Return a borrowed schema (no finalizer, won't be freed)
	return &Schema{
		cSchema:  cSchema,
		borrowed: true,
	}
}

// SchemaNote returns the predefined schema for personal passwords/notes.
// This is a convenience function equivalent to GetSchema(SchemaTypeNote).
//
// Schema name: "org.gnome.keyring.Note"
// Attributes: none
//
// The returned schema is static and should NOT be freed.
func SchemaNote() *Schema {
	return GetSchema(SchemaTypeNote)
}

// SchemaCompatNetwork returns the predefined schema for network passwords.
// This is a convenience function equivalent to GetSchema(SchemaTypeCompatNetwork).
//
// Schema name: "org.gnome.keyring.NetworkPassword"
//
// Attributes:
//   - user: The user name (string)
//   - domain: The login domain or realm (string)
//   - object: The object or path (string)
//   - protocol: The protocol (string like 'http')
//   - port: The network port (integer)
//   - server: The hostname or server (string)
//   - authtype: The authentication type (string)
//
// The returned schema is static and should NOT be freed.
//
// Example:
//
//	schema := golibsecret.SchemaCompatNetwork()
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("user", "john")
//	attrs.Set("server", "example.com")
//	attrs.Set("protocol", "https")
//	attrs.Set("port", "443")
//	defer attrs.Free()
//
//	password, err := golibsecret.PasswordLookupSync(schema, attrs)
func SchemaCompatNetwork() *Schema {
	return GetSchema(SchemaTypeCompatNetwork)
}
