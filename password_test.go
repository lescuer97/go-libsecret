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

// Test PasswordStoreSync

func TestPasswordStoreSyncNilAttributes(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with nil attributes
	err = PasswordStoreSync(schema, nil, CollectionDefault, "Test Label", "password123")
	if err == nil {
		t.Error("PasswordStoreSync with nil attributes expected error, got none")
	}
}

func TestPasswordStoreSyncEmptyLabel(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("username", "test_user")
	defer attrs.Free()

	// Test with empty label
	err = PasswordStoreSync(schema, attrs, CollectionDefault, "", "password123")
	if err == nil {
		t.Error("PasswordStoreSync with empty label expected error, got none")
	}
}

func TestPasswordStoreSyncEmptyPassword(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("username", "test_user")
	defer attrs.Free()

	// Test with empty password
	err = PasswordStoreSync(schema, attrs, CollectionDefault, "Test Label", "")
	if err == nil {
		t.Error("PasswordStoreSync with empty password expected error, got none")
	}
}

func TestPasswordStore(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("username", "test_store_user")
	defer attrs.Free()

	// Test the alias function - may fail if no secret service is running
	err = PasswordStore(schema, attrs, CollectionDefault, "Test Password", "testpass123")
	if err != nil {
		t.Logf("PasswordStore returned error (secret service might not be running): %v", err)
	}
}

func TestStorePassword(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
		"service":  SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test the convenience function with a map
	err = StorePassword(schema, map[string]string{
		"username": "test_user",
		"service":  "test_service",
	}, CollectionDefault, "Test Password", "testpass123")

	// May fail if no secret service is running
	if err != nil {
		t.Logf("StorePassword returned error (secret service might not be running): %v", err)
	}
}

func TestStorePasswordEmptyMap(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"username": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with empty map
	err = StorePassword(schema, map[string]string{}, CollectionDefault, "Test", "pass")
	if err == nil {
		t.Error("StorePassword with empty map expected error, got none")
	}
}

// Test PasswordStoreBinarySync

func TestPasswordStoreBinarySyncNilAttributes(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	value, err := NewValue("secret", -1, "text/plain")
	if err != nil {
		t.Fatalf("NewValue() failed: %v", err)
	}
	defer value.Unref()

	// Test with nil attributes
	err = PasswordStoreBinarySync(schema, nil, CollectionDefault, "Test Label", value)
	if err == nil {
		t.Error("PasswordStoreBinarySync with nil attributes expected error, got none")
	}
}

func TestPasswordStoreBinarySyncEmptyLabel(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("service", "test_service")
	defer attrs.Free()

	value, err := NewValue("secret", -1, "text/plain")
	if err != nil {
		t.Fatalf("NewValue() failed: %v", err)
	}
	defer value.Unref()

	// Test with empty label
	err = PasswordStoreBinarySync(schema, attrs, CollectionDefault, "", value)
	if err == nil {
		t.Error("PasswordStoreBinarySync with empty label expected error, got none")
	}
}

func TestPasswordStoreBinarySyncNilValue(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("service", "test_service")
	defer attrs.Free()

	// Test with nil value
	err = PasswordStoreBinarySync(schema, attrs, CollectionDefault, "Test Label", nil)
	if err == nil {
		t.Error("PasswordStoreBinarySync with nil value expected error, got none")
	}
}

func TestPasswordStoreBinary(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("service", "test_binary_service")
	defer attrs.Free()

	value, err := NewValueFromBytes([]byte{0x01, 0x02, 0x03, 0x04}, "application/octet-stream")
	if err != nil {
		t.Fatalf("NewValueFromBytes() failed: %v", err)
	}
	defer value.Unref()

	// Test the alias function - may fail if no secret service is running
	err = PasswordStoreBinary(schema, attrs, CollectionDefault, "Test Binary Secret", value)
	if err != nil {
		t.Logf("PasswordStoreBinary returned error (secret service might not be running): %v", err)
	}
}

func TestStoreBinarySecret(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	value, err := NewValueFromBytes([]byte{0x01, 0x02, 0x03, 0x04}, "application/octet-stream")
	if err != nil {
		t.Fatalf("NewValueFromBytes() failed: %v", err)
	}
	defer value.Unref()

	// Test the convenience function with a map
	err = StoreBinarySecret(schema, map[string]string{
		"service": "test_binary_service",
	}, CollectionDefault, "Test Binary Secret", value)

	// May fail if no secret service is running
	if err != nil {
		t.Logf("StoreBinarySecret returned error (secret service might not be running): %v", err)
	}
}

func TestStoreBinarySecretEmptyMap(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	value, err := NewValue("secret", -1, "text/plain")
	if err != nil {
		t.Fatalf("NewValue() failed: %v", err)
	}
	defer value.Unref()

	// Test with empty map
	err = StoreBinarySecret(schema, map[string]string{}, CollectionDefault, "Test", value)
	if err == nil {
		t.Error("StoreBinarySecret with empty map expected error, got none")
	}
}

// Test collection constants

func TestCollectionConstants(t *testing.T) {
	if CollectionDefault != "default" {
		t.Errorf("CollectionDefault = %q, want %q", CollectionDefault, "default")
	}
	if CollectionSession != "session" {
		t.Errorf("CollectionSession = %q, want %q", CollectionSession, "session")
	}
}

// Test SearchFlags

func TestSearchFlagsString(t *testing.T) {
	tests := []struct {
		flags    SearchFlags
		expected string
	}{
		{SearchFlagsNone, "NONE"},
		{SearchFlagsAll, "ALL"},
		{SearchFlagsUnlock, "UNLOCK"},
		{SearchFlagsLoadSecrets, "LOAD_SECRETS"},
		{SearchFlags(999), "FLAGS(999)"},
	}

	for _, test := range tests {
		if got := test.flags.String(); got != test.expected {
			t.Errorf("SearchFlags(%d).String() = %q, want %q", test.flags, got, test.expected)
		}
	}
}

// Test PasswordSearchSync

func TestPasswordSearchSyncNilAttributes(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with nil attributes
	_, err = PasswordSearchSync(schema, nil, SearchFlagsNone)
	if err == nil {
		t.Error("PasswordSearchSync with nil attributes expected error, got none")
	}
}

func TestPasswordSearchSyncNoResults(t *testing.T) {
	schema, err := NewSchema("org.example.NonExistent", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("service", "nonexistent_service_xyz_12345")
	defer attrs.Free()

	// Search for something that doesn't exist
	results, err := PasswordSearchSync(schema, attrs, SearchFlagsAll)

	// May fail if no secret service is running
	if err != nil {
		t.Logf("PasswordSearchSync returned error (secret service might not be running): %v", err)
		return
	}

	// Should return empty slice, not error
	if len(results) != 0 {
		t.Errorf("PasswordSearchSync expected 0 results, got %d", len(results))
		for _, r := range results {
			r.Free()
		}
	}
}

func TestPasswordSearch(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("service", "test_search_service")
	defer attrs.Free()

	// Test the alias function
	results, err := PasswordSearch(schema, attrs, SearchFlagsAll)
	if err != nil {
		t.Logf("PasswordSearch returned error (secret service might not be running): %v", err)
		return
	}

	t.Logf("PasswordSearch found %d results", len(results))
	for _, r := range results {
		t.Logf("  - Label: %s, Attrs: %v", r.GetLabel(), r.GetAttributes())
		r.Free()
	}
}

func TestSearchPasswords(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test the convenience function with a map
	results, err := SearchPasswords(schema, map[string]string{
		"service": "test_search_service",
	}, SearchFlagsAll)

	if err != nil {
		t.Logf("SearchPasswords returned error (secret service might not be running): %v", err)
		return
	}

	t.Logf("SearchPasswords found %d results", len(results))
	for _, r := range results {
		r.Free()
	}
}

func TestSearchPasswordsEmptyMap(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with empty map
	_, err = SearchPasswords(schema, map[string]string{}, SearchFlagsAll)
	if err == nil {
		t.Error("SearchPasswords with empty map expected error, got none")
	}
}

func TestSearchResultMethods(t *testing.T) {
	// Test with nil SearchResult
	r := &SearchResult{cRetrievable: nil}

	if attrs := r.GetAttributes(); attrs != nil {
		t.Error("GetAttributes on nil result should return nil")
	}

	if label := r.GetLabel(); label != "" {
		t.Error("GetLabel on nil result should return empty string")
	}

	if created := r.GetCreated(); created != 0 {
		t.Error("GetCreated on nil result should return 0")
	}

	if modified := r.GetModified(); modified != 0 {
		t.Error("GetModified on nil result should return 0")
	}

	_, err := r.RetrieveSecret()
	if err == nil {
		t.Error("RetrieveSecret on nil result should return error")
	}

	// String should not panic
	str := r.String()
	if str != "SearchResult{nil}" {
		t.Errorf("String on nil result = %q, want %q", str, "SearchResult{nil}")
	}

	// Free should not panic
	r.Free()
}

// Test PasswordClearSync

func TestPasswordClearSyncNilAttributes(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with nil attributes
	_, err = PasswordClearSync(schema, nil)
	if err == nil {
		t.Error("PasswordClearSync with nil attributes expected error, got none")
	}
}

func TestPasswordClearSyncNonExistent(t *testing.T) {
	schema, err := NewSchema("org.example.NonExistent", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("service", "nonexistent_service_xyz_clear_12345")
	defer attrs.Free()

	// Try to clear something that doesn't exist
	removed, err := PasswordClearSync(schema, attrs)

	// May fail if no secret service is running
	if err != nil {
		t.Logf("PasswordClearSync returned error (secret service might not be running): %v", err)
		return
	}

	// Should return false (nothing removed)
	if removed {
		t.Error("PasswordClearSync expected false for non-existent password, got true")
	}
}

func TestPasswordClear(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	attrs := NewAttributes()
	attrs.Set("service", "test_clear_service")
	defer attrs.Free()

	// Test the alias function
	removed, err := PasswordClear(schema, attrs)
	if err != nil {
		t.Logf("PasswordClear returned error (secret service might not be running): %v", err)
		return
	}

	t.Logf("PasswordClear removed: %v", removed)
}

func TestClearPassword(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test the convenience function with a map
	removed, err := ClearPassword(schema, map[string]string{
		"service": "test_clear_service",
	})

	if err != nil {
		t.Logf("ClearPassword returned error (secret service might not be running): %v", err)
		return
	}

	t.Logf("ClearPassword removed: %v", removed)
}

func TestClearPasswordEmptyMap(t *testing.T) {
	schema, err := NewSchema("org.example.Test", SchemaFlagsNone, map[string]SchemaAttributeType{
		"service": SchemaAttributeString,
	})
	if err != nil {
		t.Fatalf("NewSchema() failed: %v", err)
	}
	defer schema.Unref()

	// Test with empty map
	_, err = ClearPassword(schema, map[string]string{})
	if err == nil {
		t.Error("ClearPassword with empty map expected error, got none")
	}
}
