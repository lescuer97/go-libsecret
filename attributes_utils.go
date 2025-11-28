package golibsecret

import "fmt"

// BuildAttributes is a convenience function that creates a new Attributes
// object from a list of key-value pairs. This is the Go equivalent of
// the C secret_attributes_build() function.
//
// The function takes a variadic number of arguments and expects an even
// number of arguments (key-value pairs). Each key should be a string,
// and each value can be string, int, or bool.
//
// Examples:
//
//	// String values
//	attrs, err := golibsecret.BuildAttributes("username", "john", "url", "https://example.com")
//	
//	// Mixed types - all converted to strings
//	attrs, err := golibsecret.BuildAttributes(
//	    "username", "john",
//	    "port", 8080,          // integer converted to "8080"
//	    "ssl", true,           // boolean converted to "true"
//	)
//	
//	// NULL-terminated list
//	attrs, err := golibsecret.BuildAttributes("username", "john", "url", "https://example.com", nil)
func BuildAttributes(args ...interface{}) (*Attributes, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one key-value pair is required")
	}

	// Handle single nil terminator
	if len(args) == 1 && args[0] == nil {
		return NewAttributes(), nil
	}

	// Count non-nil arguments to check for pairs
	// Check if last argument is nil (terminator)
	effectiveArgs := args
	if len(args) > 0 && args[len(args)-1] == nil {
		effectiveArgs = args[:len(args)-1]
	}

	if len(effectiveArgs)%2 != 0 {
		return nil, fmt.Errorf("arguments must be pairs of key-value: got %d arguments", len(args))
	}

	attrs := NewAttributes()

	for i := 0; i < len(effectiveArgs); i += 2 {
		// Check for nil terminator in the middle of arguments
		if effectiveArgs[i] == nil {
			break
		}

		// Extract key (must be string)
		key, ok := effectiveArgs[i].(string)
		if !ok {
			attrs.free()
			return nil, fmt.Errorf("argument %d must be a string key", i)
		}

		// Extract value
		if i+1 >= len(effectiveArgs) {
			attrs.free()
			return nil, fmt.Errorf("missing value for key %q", key)
		}

		value := effectiveArgs[i+1]
		
		var valueStr string
		switch v := value.(type) {
		case string:
			valueStr = v
		case int, int8, int16, int32, int64:
			valueStr = fmt.Sprintf("%d", v)
		case uint, uint8, uint16, uint32, uint64:
			valueStr = fmt.Sprintf("%d", v)
		case bool:
			if v {
				valueStr = "true"
			} else {
				valueStr = "false"
			}
		case nil:
			valueStr = ""
		default:
			attrs.free()
			return nil, fmt.Errorf("unsupported type %T for value of key %q", v, key)
		}

		if err := attrs.Set(key, valueStr); err != nil {
			attrs.free()
			return nil, fmt.Errorf("failed to set attribute %q: %w", key, err)
		}
	}

	return attrs, nil
}

// BuildAttributesV is a variadic version of BuildAttributes that explicitly
// takes a variable list of arguments. This is more type-safe than BuildAttributes
// when the types are known at compile time.
//
// The function takes a schema and then a variable number of key-value pairs.
// This function validates the attributes against the schema types.
//
// Examples:
//
//	attrs, err := golibsecret.BuildAttributesV(
//	    schema,
//	    "username", "john",
//	    "port", 8080,
//	    "ssl", true,
//	)
func BuildAttributesV(schema *Schema, args ...interface{}) (*Attributes, error) {
	if schema == nil {
		return nil, fmt.Errorf("schema cannot be nil")
	}

	attrs, err := BuildAttributes(args...)
	if err != nil {
		return nil, fmt.Errorf("failed to build attributes: %w", err)
	}

	// Validate against schema if provided
	if schema.cSchema != nil {
		if err := attrs.validateAgainstSchema(schema); err != nil {
			attrs.free()
			return nil, fmt.Errorf("attribute validation failed: %w", err)
		}
	}

	return attrs, nil
}

// validateAgainstSchema validates that the attributes conform to the schema
// definition. This includes checking that all required attributes are present
// and that their types are correct.
func (a *Attributes) validateAgainstSchema(schema *Schema) error {
	if schema == nil || schema.cSchema == nil {
		return nil // No schema to validate against
	}

	schemaAttrs := schema.Attributes()
	
	// Check each attribute against schema
	for key, value := range a.ToMap() {
		if schemaType, ok := schemaAttrs[key]; ok {
			// Validate the value type based on schema expectations
			if !a.validateAttributeValue(value, schemaType) {
				return fmt.Errorf("attribute %q has invalid value %q for type %s", 
					key, value, schemaType.String())
			}
		} else {
			return fmt.Errorf("attribute %q is not defined in schema", key)
		}
	}

	// Check that all schema attributes are present
	for schemaKey := range schemaAttrs {
		if !a.Has(schemaKey) {
			return fmt.Errorf("required attribute %q is missing", schemaKey)
		}
	}

	return nil
}

// validateAttributeValue validates that a string value conforms to the
// expected schema attribute type.
func (a *Attributes) validateAttributeValue(value string, attrType SchemaAttributeType) bool {
	switch attrType {
	case SchemaAttributeString:
		return true // All strings are valid string attributes

	case SchemaAttributeInteger:
		// Integer values must be valid decimal representations
		if value == "" || value == "-" {
			return false
		}
		for _, r := range value {
			if r < '0' || r > '9' {
				if r != '-' { // Allow negative sign at start
					return false
				}
			}
		}
		return true

	case SchemaAttributeBoolean:
		// Boolean values must be "true" or "false"
		return value == "true" || value == "false"

	default:
		return false
	}
}

// ValidateAttributesAgainstSchema validates that a set of attributes
// conforms to the given schema without modifying the attributes.
//
// This is useful for pre-validation before operations that might fail.
//
// Example:
//
//	attrs := golibsecret.NewAttributes()
//	attrs.Set("username", "john")
//	
//	err := golibsecret.ValidateAttributesAgainstSchema(schema, attrs)
//	if err != nil {
//	    log.Fatal(err)
//	}
func ValidateAttributesAgainstSchema(schema *Schema, attrs *Attributes) error {
	if schema == nil {
		return fmt.Errorf("schema cannot be nil")
	}
	if attrs == nil {
		return fmt.Errorf("attributes cannot be nil")
	}

	return attrs.validateAgainstSchema(schema)
}

// NormalizeBooleanAttribute normalizes boolean attribute values to the
// canonical "true" or "false" string representation.
//
// Example:
//
//	normalized := golibsecret.NormalizeBooleanAttribute("TRUE")  // returns "true"
//	normalized = golibsecret.NormalizeBooleanAttribute("false") // returns "false"
//	normalized = golibsecret.NormalizeBooleanAttribute(1)       // returns "true"
func NormalizeBooleanAttribute(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		switch v {
		case "true", "TRUE", "True", "1":
			return "true", nil
		case "false", "FALSE", "False", "0":
			return "false", nil
		default:
			return "", fmt.Errorf("invalid boolean value: %q", v)
		}
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case int, int8, int16, int32, int64:
		if v == 0 {
			return "false", nil
		}
		return "true", nil
	case uint, uint8, uint16, uint32, uint64:
		if v == 0 {
			return "false", nil
		}
		return "true", nil
	default:
		return "", fmt.Errorf("cannot convert type %T to boolean", v)
	}
}

// NormalizeIntegerAttribute normalizes integer attribute values to their
// string decimal representation.
//
// Example:
//
//	normalized := golibsecret.NormalizeIntegerAttribute(8080)    // returns "8080"
//	normalized = golibsecret.NormalizeIntegerAttribute("-42")   // returns "-42"
func NormalizeIntegerAttribute(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		// Validate that it's a valid integer string
		if v == "" {
			return "", fmt.Errorf("integer value cannot be empty")
		}
		// Try to parse as integer to validate
		// We don't need the actual value, just validation
		_, err := fmt.Sscanf(v, "%d", new(int))
		if err != nil {
			return "", fmt.Errorf("invalid integer value: %q", v)
		}
		return v, nil
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", v), nil
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v), nil
	default:
		return "", fmt.Errorf("cannot convert type %T to integer", v)
	}
}

// AttributeBuilder provides a fluent API for building attributes.
// This is useful when building attributes dynamically or when you want
// method chaining for cleaner code.
//
// Example:
//
//	attrs, err := golibsecret.NewAttributeBuilder().
//	    WithString("username", "john").
//	    WithInteger("port", 8080).
//	    WithBoolean("ssl", true).
//	    Build()
type AttributeBuilder struct {
	attrs *Attributes
}

// NewAttributeBuilder creates a new attribute builder.
func NewAttributeBuilder() *AttributeBuilder {
	return &AttributeBuilder{
		attrs: NewAttributes(),
	}
}

// WithString adds a string attribute.
func (b *AttributeBuilder) WithString(key, value string) *AttributeBuilder {
	if b.attrs != nil {
		b.attrs.Set(key, value)
	}
	return b
}

// WithInteger adds an integer attribute (will be converted to string).
func (b *AttributeBuilder) WithInteger(key string, value int) *AttributeBuilder {
	if b.attrs != nil {
		b.attrs.Set(key, fmt.Sprintf("%d", value))
	}
	return b
}

// WithBoolean adds a boolean attribute (will be converted to "true" or "false").
func (b *AttributeBuilder) WithBoolean(key string, value bool) *AttributeBuilder {
	if b.attrs != nil {
		valueStr := "false"
		if value {
			valueStr = "true"
		}
		b.attrs.Set(key, valueStr)
	}
	return b
}

// Build constructs the final Attributes object.
// Remember to call Free() on the returned object when done.
func (b *AttributeBuilder) Build() (*Attributes, error) {
	attrs := b.attrs
	b.attrs = nil // Prevent double-free
	return attrs, nil
}

// Free frees the builder's internal resources if not already built.
func (b *AttributeBuilder) Free() {
	if b.attrs != nil {
		b.attrs.free()
		b.attrs = nil
	}
}
