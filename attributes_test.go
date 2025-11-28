package golibsecret

import (
	"testing"
)

func TestBuildAttributes(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		wantErr  bool
		validate func(*Attributes) error
	}{
		{
			name:    "empty arguments",
			args:    []interface{}{},
			wantErr: true,
		},
		{
			name:    "odd number of arguments",
			args:    []interface{}{"key1"},
			wantErr: true,
		},
		{
			name: "string values",
			args: []interface{}{"username", "john", "url", "https://example.com"},
			validate: func(a *Attributes) error {
				if a.Get("username") != "john" {
					t.Errorf("username = %q, want %q", a.Get("username"), "john")
				}
				if a.Get("url") != "https://example.com" {
					t.Errorf("url = %q, want %q", a.Get("url"), "https://example.com")
				}
				return nil
			},
		},
		{
			name: "integer values",
			args: []interface{}{"port", 8080, "count", int64(100)},
			validate: func(a *Attributes) error {
				if a.Get("port") != "8080" {
					t.Errorf("port = %q, want %q", a.Get("port"), "8080")
				}
				if a.Get("count") != "100" {
					t.Errorf("count = %q, want %q", a.Get("count"), "100")
				}
				return nil
			},
		},
		{
			name: "boolean values",
			args: []interface{}{"ssl", true, "verified", false},
			validate: func(a *Attributes) error {
				if a.Get("ssl") != "true" {
					t.Errorf("ssl = %q, want %q", a.Get("ssl"), "true")
				}
				if a.Get("verified") != "false" {
					t.Errorf("verified = %q, want %q", a.Get("verified"), "false")
				}
				return nil
			},
		},
		{
			name: "mixed types",
			args: []interface{}{
				"username", "john",
				"port", 8080,
				"ssl", true,
			},
			validate: func(a *Attributes) error {
				if a.Len() != 3 {
					t.Errorf("length = %d, want 3", a.Len())
				}
				return nil
			},
		},
		{
			name: "nil terminator",
			args: []interface{}{"username", "john", nil},
			validate: func(a *Attributes) error {
				if a.Len() != 1 {
					t.Errorf("length = %d, want 1", a.Len())
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attrs, err := BuildAttributes(test.args...)

			if test.wantErr {
				if err == nil {
					t.Errorf("BuildAttributes() expected error, got none")
					return
				}
			} else {
				if err != nil {
					t.Errorf("BuildAttributes() unexpected error: %v", err)
					return
				}
				if attrs == nil {
					t.Errorf("BuildAttributes() returned nil")
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

func TestBuildAttributesV(t *testing.T) {
	schema, err := NewSchema("org.example.Schema", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
		"port":     SchemaAttributeInteger,
		"ssl":      SchemaAttributeBoolean,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	tests := []struct {
		name     string
		schema   *Schema
		args     []interface{}
		wantErr  bool
		validate func(*Attributes) error
	}{
		{
			name:    "nil schema",
			schema:  nil,
			args:    []interface{}{"username", "john"},
			wantErr: true,
		},
		{
			name:   "valid attributes matching schema",
			schema: schema,
			args: []interface{}{
				"username", "john",
				"port", 8080,
				"ssl", true,
			},
			wantErr: false,
			validate: func(a *Attributes) error {
				if a.Len() != 3 {
					t.Errorf("length = %d, want 3", a.Len())
				}
				return nil
			},
		},
		{
			name:   "extra attribute not in schema",
			schema: schema,
			args: []interface{}{
				"username", "john",
				"port", 8080,
				"ssl", true,
				"extra", "value",
			},
			wantErr: true, // Should fail validation
		},
		{
			name:   "missing required attribute",
			schema: schema,
			args: []interface{}{
				"username", "john",
				// Missing port and ssl
			},
			wantErr: true, // Should fail validation
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attrs, err := BuildAttributesV(test.schema, test.args...)

			if test.wantErr {
				if err == nil {
					t.Errorf("BuildAttributesV() expected error, got none")
					return
				}
			} else {
				if err != nil {
					t.Errorf("BuildAttributesV() unexpected error: %v", err)
					return
				}
				if attrs == nil {
					t.Errorf("BuildAttributesV() returned nil")
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

func TestValidateAttributesAgainstSchema(t *testing.T) {
	schema, err := NewSchema("org.example.Schema", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
		"port":     SchemaAttributeInteger,
		"ssl":      SchemaAttributeBoolean,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	tests := []struct {
		name    string
		attrs   *Attributes
		wantErr bool
	}{
		{
			name: "valid attributes",
			attrs: func() *Attributes {
				a := NewAttributes()
				a.Set("username", "john")
				a.Set("port", "8080")
				a.Set("ssl", "true")
				return a
			}(),
			wantErr: false,
		},
		{
			name: "extra attribute",
			attrs: func() *Attributes {
				a := NewAttributes()
				a.Set("username", "john")
				a.Set("port", "8080")
				a.Set("ssl", "true")
				a.Set("extra", "value")
				return a
			}(),
			wantErr: true,
		},
		{
			name: "missing attribute",
			attrs: func() *Attributes {
				a := NewAttributes()
				a.Set("username", "john")
				a.Set("port", "8080")
				// Missing ssl
				return a
			}(),
			wantErr: true,
		},
		{
			name: "invalid boolean value",
			attrs: func() *Attributes {
				a := NewAttributes()
				a.Set("username", "john")
				a.Set("port", "8080")
				a.Set("ssl", "yes") // Should be "true" or "false"
				return a
			}(),
			wantErr: true,
		},
		{
			name: "invalid integer value",
			attrs: func() *Attributes {
				a := NewAttributes()
				a.Set("username", "john")
				a.Set("port", "not-a-number")
				a.Set("ssl", "true")
				return a
			}(),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.attrs != nil {
				defer test.attrs.Free()
			}

			err := ValidateAttributesAgainstSchema(schema, test.attrs)

			if test.wantErr {
				if err == nil {
					t.Errorf("ValidateAttributesAgainstSchema() expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("ValidateAttributesAgainstSchema() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestNormalizeBooleanAttribute(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
		wantErr  bool
	}{
		{"true string", "true", "true", false},
		{"TRUE string", "TRUE", "true", false},
		{"false string", "false", "false", false},
		{"FALSE string", "FALSE", "false", false},
		{"1 string", "1", "true", false},
		{"0 string", "0", "false", false},
		{"true bool", true, "true", false},
		{"false bool", false, "false", false},
		{"1 int", 1, "true", false},
		{"0 int", 0, "false", false},
		{"42 int", 42, "true", false},
		{"invalid string", "yes", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeBooleanAttribute(test.value)

			if test.wantErr {
				if err == nil {
					t.Errorf("NormalizeBooleanAttribute() expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("NormalizeBooleanAttribute() unexpected error: %v", err)
				} else if got != test.expected {
					t.Errorf("NormalizeBooleanAttribute() = %q, want %q", got, test.expected)
				}
			}
		})
	}
}

func TestNormalizeIntegerAttribute(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
		wantErr  bool
	}{
		{"positive int", 42, "42", false},
		{"negative int", -42, "-42", false},
		{"zero int", 0, "0", false},
		{"positive string", "42", "42", false},
		{"negative string", "-42", "-42", false},
		{"uint", uint(42), "42", false},
		{"empty string", "", "", true},
		{"invalid string", "not-a-number", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeIntegerAttribute(test.value)

			if test.wantErr {
				if err == nil {
					t.Errorf("NormalizeIntegerAttribute() expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("NormalizeIntegerAttribute() unexpected error: %v", err)
				} else if got != test.expected {
					t.Errorf("NormalizeIntegerAttribute() = %q, want %q", got, test.expected)
				}
			}
		})
	}
}

func TestAttributeBuilder(t *testing.T) {
	builder := NewAttributeBuilder()

	attrs, err := builder.
		WithString("username", "john").
		WithInteger("port", 8080).
		WithBoolean("ssl", true).
		Build()

	if err != nil {
		t.Fatalf("AttributeBuilder.Build() failed: %v", err)
	}
	defer attrs.Free()

	// Verify all attributes were set correctly
	tests := []struct {
		key      string
		expected string
	}{
		{"username", "john"},
		{"port", "8080"},
		{"ssl", "true"},
	}

	for _, test := range tests {
		if got := attrs.Get(test.key); got != test.expected {
			t.Errorf("attrs.Get(%q) = %q, want %q", test.key, got, test.expected)
		}
	}

	if attrs.Len() != 3 {
		t.Errorf("attrs.Len() = %d, want 3", attrs.Len())
	}
}

func TestAttributeBuilderFree(t *testing.T) {
	builder := NewAttributeBuilder()
	builder.WithString("username", "john")

	// Free without building
	builder.Free()

	// Building after free should return nil
	attrs, err := builder.Build()
	if err != nil {
		t.Errorf("Build() after Free() unexpected error: %v", err)
	}
	if attrs != nil {
		defer attrs.Free()
		t.Errorf("Build() after Free() should return nil, got non-nil")
	}
}

func BenchmarkBuildAttributes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		attrs, _ := BuildAttributes(
			"username", "john",
			"port", 8080,
			"ssl", true,
		)
		if attrs != nil {
			attrs.Free()
		}
	}
}

func BenchmarkAttributeBuilder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		attrs, _ := NewAttributeBuilder().
			WithString("username", "john").
			WithInteger("port", 8080).
			WithBoolean("ssl", true).
			Build()
		if attrs != nil {
			attrs.Free()
		}
	}
}

func BenchmarkAttributesFromMap(b *testing.B) {
	attrMap := map[string]string{
		"username": "john",
		"port":     "8080",
		"ssl":      "true",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		attrs, _ := AttributesFromMap(attrMap)
		if attrs != nil {
			attrs.Free()
		}
	}
}
