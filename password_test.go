package golibsecret

import (
	"testing"
)

func TestPasswordLookupSyncNilAttributes(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with nil attributes
	_, err = PasswordLookupSync(schema, nil)
	if err == nil {
		t.Error("PasswordLookupSync(schema, nil) expected error, got none")
	}
}

func TestPasswordLookupSyncNilSchema(t *testing.T) {
	attrs := NewAttributes()
	attrs.Set("username", "test")
	defer attrs.Free()

	// Test with nil schema - should still work (matches any schema)
	// This will return empty string if no password found, which is not an error
	_, err := PasswordLookupSync(nil, attrs)
	// Note: This might return an error if no secret service is running,
	// or empty string if no matching password found
	// We just verify it doesn't panic
	_ = err
}

func TestPasswordLookupSyncNotFound(t *testing.T) {
	schema, err := NewSchema("org.example.NonExistent", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
		"service":  SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("username", "nonexistent_user_12345")
	attrs.Set("service", "nonexistent_service_67890")
	defer attrs.Free()

	// Lookup a password that doesn't exist
	password, err := PasswordLookupSync(schema, attrs)

	// If secret service is not running, we might get an error
	// If it is running, we should get empty string (not found)
	if err != nil {
		t.Logf("PasswordLookupSync returned error (secret service might not be running): %v", err)
		return
	}

	if password != "" {
		t.Errorf("PasswordLookupSync() expected empty string for non-existent password, got %q", password)
	}
}

func TestPasswordLookup(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("username", "test_lookup_user")
	defer attrs.Free()

	// Test the alias function
	password, err := PasswordLookup(schema, attrs)

	// We don't assert on the result since it depends on the secret service state
	// Just verify it doesn't panic and returns sensible values
	if err != nil {
		t.Logf("PasswordLookup returned error: %v", err)
	} else {
		t.Logf("PasswordLookup returned password length: %d", len(password))
	}
}

func TestLookupPassword(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
		"service":  SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test the convenience function with a map
	password, err := LookupPassword(schema, map[string]string{
		"username": "test_user",
		"service":  "test_service",
	})

	// We don't assert on the result since it depends on the secret service state
	if err != nil {
		t.Logf("LookupPassword returned error: %v", err)
	} else {
		t.Logf("LookupPassword returned password length: %d", len(password))
	}
}

func TestLookupPasswordEmptyMap(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with empty map
	_, err = LookupPassword(schema, map[string]string{})
	if err == nil {
		t.Error("LookupPassword with empty map expected error, got none")
	}
}

func TestLookupPasswordNilMap(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with nil map
	_, err = LookupPassword(schema, nil)
	if err == nil {
		t.Error("LookupPassword with nil map expected error, got none")
	}
}

