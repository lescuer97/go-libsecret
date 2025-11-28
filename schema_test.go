package golibsecret

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSchemaAttributeTypeString(t *testing.T) {
	tests := []struct {
		attrType SchemaAttributeType
		expected string
	}{
		{SchemaAttributeString, "STRING"},
		{SchemaAttributeInteger, "INTEGER"},
		{SchemaAttributeBoolean, "BOOLEAN"},
		{SchemaAttributeType(999), "UNKNOWN(999)"},
	}

	for _, test := range tests {
		if got := test.attrType.String(); got != test.expected {
			t.Errorf("SchemaAttributeType(%d).String() = %q, want %q", test.attrType, got, test.expected)
		}
	}
}

func TestSchemaFlagsString(t *testing.T) {
	tests := []struct {
		flags    SchemaFlags
		expected string
	}{
		{SchemaFlagsNone, "NONE"},
		{SchemaFlagsDontMatchName, "DONT_MATCH_NAME"},
		{SchemaFlags(999), "FLAGS(999)"},
	}

	for _, test := range tests {
		if got := test.flags.String(); got != test.expected {
			t.Errorf("SchemaFlags(%d).String() = %q, want %q", test.flags, got, test.expected)
		}
	}
}

func TestNewSchema(t *testing.T) {
	tests := []struct {
		testName   string
		schemaName string
		flags      SchemaFlags
		attributes map[string]SchemaAttributeType
		wantErr    bool
		errContains string
	}{
		{
			testName:   "empty name",
			schemaName: "",
			flags:      SchemaFlagsNone,
			attributes: map[string]SchemaAttributeType{"key": SchemaAttributeString},
			wantErr:    true,
			errContains: "schema name cannot be empty",
		},
		{
			testName:   "empty attributes",
			schemaName: "org.example.Schema",
			flags:      SchemaFlagsNone,
			attributes: map[string]SchemaAttributeType{},
			wantErr:    true,
			errContains: "schema must have at least one attribute",
		},
		{
			testName:   "too many attributes",
			schemaName: "org.example.Schema",
			flags:      SchemaFlagsNone,
			attributes: func() map[string]SchemaAttributeType {
				attrs := make(map[string]SchemaAttributeType)
				for i := 0; i <= 32; i++ {
					attrs[fmt.Sprintf("attr%d", i)] = SchemaAttributeString
				}
				return attrs
			}(),
			wantErr:     true,
			errContains: "schema cannot have more than 32 attributes",
		},
		{
			testName:   "valid schema with string attribute",
			schemaName: "org.example.Schema",
			flags:      SchemaFlagsNone,
			attributes: map[string]SchemaAttributeType{
				"username": SchemaAttributeString,
			},
			wantErr: false,
		},
		{
			testName:   "valid schema with mixed attributes",
			schemaName: "org.example.Schema",
			flags:      SchemaFlagsNone,
			attributes: map[string]SchemaAttributeType{
				"username": SchemaAttributeString,
				"port":     SchemaAttributeInteger,
				"ssl":      SchemaAttributeBoolean,
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			schema, err := NewSchema(test.schemaName, test.flags, test.attributes)

			if test.wantErr {
				if err == nil {
					t.Errorf("NewSchema() expected error, got none")
					return
				}
				if test.errContains != "" && !contains(err.Error(), test.errContains) {
					t.Errorf("NewSchema() error = %v, want error containing %q", err, test.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("NewSchema() unexpected error: %v", err)
					return
				}
				if schema == nil {
					t.Errorf("NewSchema() returned nil schema")
					return
				}
				defer schema.Unref()

				// Verify schema properties
				if schema.Name() != test.schemaName {
					t.Errorf("schema.Name() = %q, want %q", schema.Name(), test.schemaName)
				}
				if schema.Flags() != test.flags {
					t.Errorf("schema.Flags() = %v, want %v", schema.Flags(), test.flags)
				}

				attrs := schema.Attributes()
				if len(attrs) != len(test.attributes) {
					t.Errorf("schema.Attributes() length = %d, want %d", len(attrs), len(test.attributes))
				}

				for key, expectedType := range test.attributes {
					if actualType, ok := attrs[key]; !ok {
						t.Errorf("schema.Attributes() missing key %q", key)
					} else if actualType != expectedType {
						t.Errorf("schema.Attributes()[%q] = %v, want %v", key, actualType, expectedType)
					}
				}
			}
		})
	}
}

func TestSchemaUnref(t *testing.T) {
	schema, err := NewSchema("org.example.Schema", SchemaFlagsNone, map[string]SchemaAttributeType{
		"key": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}

	// Calling Unref should not panic
	schema.Unref()

	// After Unref, the schema should be invalid
	if schema.Name() != "" {
		t.Errorf("After Unref, schema.Name() should return empty string, got %q", schema.Name())
	}
}

func TestNewValue(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		length  int
		content string
		wantErr bool
	}{
		{
			name:    "empty secret",
			secret:  "",
			length:  -1,
			content: "text/plain",
			wantErr: true,
		},
		{
			name:    "valid text secret",
			secret:  "my-secret-password",
			length:  -1,
			content: "text/plain",
			wantErr: false,
		},
		{
			name:    "valid text secret with explicit length",
			secret:  "my-secret-password",
			length:  18,
			content: "text/plain",
			wantErr: false,
		},
		{
			name:    "valid secret with custom content type",
			secret:  "json-secret",
			length:  -1,
			content: "application/json",
			wantErr: false,
			// Note: GetText() will fail for non-text content types, but that's expected
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := NewValue(test.secret, test.length, test.content)

			if test.wantErr {
				if err == nil {
					t.Errorf("NewValue() expected error, got none")
					return
				}
			} else {
				if err != nil {
					t.Errorf("NewValue() unexpected error: %v", err)
					return
				}
				if value == nil {
					t.Errorf("NewValue() returned nil value")
					return
				}
				defer value.Unref()

				// Verify value properties
				contentType, err := value.GetContentType()
				if err != nil {
					t.Errorf("GetContentType() failed: %v", err)
				} else if contentType != test.content {
					t.Errorf("GetContentType() = %q, want %q", contentType, test.content)
				}

				// GetText() only works for text/plain content types
				if test.content == "text/plain" {
					secret, err := value.GetText()
					if err != nil {
						t.Errorf("GetText() failed: %v", err)
					} else if secret != test.secret {
						t.Errorf("GetText() = %q, want %q", secret, test.secret)
					}
				} else {
					// For non-text content types, GetText() should fail
					_, err := value.GetText()
					if err == nil {
						t.Errorf("GetText() should fail for non-text content type %q", test.content)
					}
				}

				if value.Len() != len(test.secret) {
					t.Errorf("Len() = %d, want %d", value.Len(), len(test.secret))
				}
			}
		})
	}
}

func TestNewValueFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		content string
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			content: "application/octet-stream",
			wantErr: true,
		},
		{
			name:    "valid binary data",
			data:    []byte{0x4b, 0x45, 0x59, 0x31, 0x32, 0x33},
			content: "application/octet-stream",
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := NewValueFromBytes(test.data, test.content)

			if test.wantErr {
				if err == nil {
					t.Errorf("NewValueFromBytes() expected error, got none")
					return
				}
			} else {
				if err != nil {
					t.Errorf("NewValueFromBytes() unexpected error: %v", err)
					return
				}
				if value == nil {
					t.Errorf("NewValueFromBytes() returned nil value")
					return
				}
				defer value.Unref()

				// Verify value properties
				data, length, err := value.Get()
				if err != nil {
					t.Errorf("Get() failed: %v", err)
				} else if !reflect.DeepEqual(data[:length], test.data) {
					t.Errorf("Get() = %v, want %v", data[:length], test.data)
				}

				contentType, err := value.GetContentType()
				if err != nil {
					t.Errorf("GetContentType() failed: %v", err)
				} else if contentType != test.content {
					t.Errorf("GetContentType() = %q, want %q", contentType, test.content)
				}
			}
		})
	}
}

func TestValueToPassword(t *testing.T) {
	originalPassword := "my-secret-password"
	value, err := NewValue(originalPassword, -1, "text/plain")
	if err != nil {
		t.Fatalf("NewValue() failed: %v", err)
	}

	password := value.ToPassword()
	if password != originalPassword {
		t.Errorf("ToPassword() = %q, want %q", password, originalPassword)
	}

	// After ToPassword(), the value should be invalid (cValue is set to nil)
	if value.cValue != nil {
		t.Errorf("After ToPassword(), value.cValue should be nil")
	}
}

func TestNewAttributes(t *testing.T) {
	attrs := NewAttributes()
	if attrs == nil {
		t.Errorf("NewAttributes() returned nil")
	}
	defer attrs.Free()

	if !attrs.IsEmpty() {
		t.Errorf("NewAttributes() should be empty")
	}

	if attrs.Len() != 0 {
		t.Errorf("NewAttributes() length should be 0, got %d", attrs.Len())
	}

	if len(attrs.Keys()) != 0 {
		t.Errorf("NewAttributes() keys should be empty, got %v", attrs.Keys())
	}
}

func TestAttributesFromMap(t *testing.T) {
	tests := []struct {
		name     string
		values   map[string]string
		wantErr  bool
		validate func(*Attributes) error
	}{
		{
			name:    "empty map",
			values:  map[string]string{},
			wantErr: true,
		},
		{
			name: "valid map",
			values: map[string]string{
				"username": "john",
				"port":     "8080",
				"ssl":      "true",
			},
			wantErr: false,
			validate: func(a *Attributes) error {
				if a.Len() != 3 {
					return fmt.Errorf("length = %d, want 3", a.Len())
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attrs, err := AttributesFromMap(test.values)

			if test.wantErr {
				if err == nil {
					t.Errorf("AttributesFromMap() expected error, got none")
					return
				}
			} else {
				if err != nil {
					t.Errorf("AttributesFromMap() unexpected error: %v", err)
					return
				}
				if attrs == nil {
					t.Errorf("AttributesFromMap() returned nil")
					return
				}
				defer attrs.Free()

				if test.validate != nil {
					if err := test.validate(attrs); err != nil {
						t.Errorf("Validation failed: %v", err)
					}
				}
			}
		})
	}
}

func TestAttributesSetGet(t *testing.T) {
	attrs := NewAttributes()
	defer attrs.Free()

	// Test Set and Get
	if err := attrs.Set("username", "john"); err != nil {
		t.Errorf("Set() failed: %v", err)
	}

	if got := attrs.Get("username"); got != "john" {
		t.Errorf("Get() = %q, want %q", got, "john")
	}

	if got := attrs.Get("nonexistent"); got != "" {
		t.Errorf("Get() for nonexistent key = %q, want empty string", got)
	}
}

func TestAttributesHasDelete(t *testing.T) {
	attrs := NewAttributes()
	defer attrs.Free()

	// Add an attribute
	attrs.Set("key", "value")

	if !attrs.Has("key") {
		t.Errorf("Has() for existing key should return true")
	}

	if attrs.Has("nonexistent") {
		t.Errorf("Has() for nonexistent key should return false")
	}

	// Delete the attribute
	if !attrs.Delete("key") {
		t.Errorf("Delete() for existing key should return true")
	}

	if attrs.Has("key") {
		t.Errorf("Has() after Delete() should return false")
	}

	// Delete nonexistent attribute
	if attrs.Delete("nonexistent") {
		t.Errorf("Delete() for nonexistent key should return false")
	}
}

func TestAttributesKeys(t *testing.T) {
	attrs := NewAttributes()
	defer attrs.Free()

	keys := []string{"username", "port", "ssl"}
	values := []string{"john", "8080", "true"}

	for i, key := range keys {
		attrs.Set(key, values[i])
	}

	gotKeys := attrs.Keys()
	if len(gotKeys) != len(keys) {
		t.Errorf("Keys() length = %d, want %d", len(gotKeys), len(keys))
	}

	for _, expectedKey := range keys {
		found := false
		for _, gotKey := range gotKeys {
			if gotKey == expectedKey {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Keys() missing expected key %q", expectedKey)
		}
	}
}

func TestAttributesToMap(t *testing.T) {
	attrs := NewAttributes()
	defer attrs.Free()

	expected := map[string]string{
		"username": "john",
		"port":     "8080",
		"ssl":      "true",
	}

	for key, value := range expected {
		attrs.Set(key, value)
	}

	got := attrs.ToMap()
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("ToMap() = %v, want %v", got, expected)
	}
}

func TestAttributesClone(t *testing.T) {
	attrs := NewAttributes()
	defer attrs.Free()

	attrs.Set("username", "john")
	attrs.Set("port", "8080")

	clone, err := attrs.Clone()
	if err != nil {
		t.Errorf("Clone() failed: %v", err)
		return
	}
	defer clone.Free()

	// Modify original
	attrs.Set("ssl", "true")

	// Clone should not be affected
	if clone.Has("ssl") {
		t.Errorf("Clone() should not be affected by changes to original")
	}

	// Modify clone
	clone.Set("domain", "example.com")

	// Original should not be affected
	if attrs.Has("domain") {
		t.Errorf("Original should not be affected by changes to clone")
	}

	// Both should have the common attributes
	if attrs.Get("username") != clone.Get("username") {
		t.Errorf("Clone should have same username as original")
	}
}

func TestAttributesEquals(t *testing.T) {
	attrs1 := NewAttributes()
	defer attrs1.Free()

	attrs2 := NewAttributes()
	defer attrs2.Free()

	attrs3 := NewAttributes()
	defer attrs3.Free()

	// Set same attributes
	attrs1.Set("username", "john")
	attrs1.Set("port", "8080")

	attrs2.Set("username", "john")
	attrs2.Set("port", "8080")

	attrs3.Set("username", "john")
	attrs3.Set("port", "8081") // Different value

	if !attrs1.Equals(attrs2) {
		t.Errorf("Equals() for identical attributes should return true")
	}

	if attrs1.Equals(attrs3) {
		t.Errorf("Equals() for different attributes should return false")
	}

	if attrs1.Equals(nil) {
		t.Errorf("Equals() for nil should return false")
	}
}

// Helper function for string containment check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (substr == "" || len(s) >= len(substr) && 
		(s == substr || len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		findSubstr(s, substr))))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
