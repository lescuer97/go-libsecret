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

// Value represents a secret value (password, token, etc.) with associated metadata.
// It provides methods to retrieve the secret data in various formats and handles
// memory management of the underlying C SecretValue structure.
//
// Mapped from C struct: SecretValue
type Value struct {
	// cValue is the underlying C SecretValue pointer
	cValue *C.SecretValue
}

// NewValue creates a new secret value from a string.
// This is a convenience method that creates a SecretValue with text content.
//
// The content type defaults to "text/plain" if not specified.
//
// Example:
//
//	// Create from string
//	value, err := NewValue("my-secret-password", -1, "text/plain")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer value.Unref()
func NewValue(secret string, length int, contentType string) (*Value, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	cSecret := C.CString(secret)
	defer C.free(unsafe.Pointer(cSecret))

	var cLength C.gssize
	if length < 0 {
		cLength = C.gssize(len(secret))
	} else {
		cLength = C.gssize(length)
	}

	var cContentType *C.gchar
	if contentType != "" {
		cContentType = C.CString(contentType)
		defer C.free(unsafe.Pointer(cContentType))
	}

	cValue := C.secret_value_new(cSecret, cLength, cContentType)
	if cValue == nil {
		return nil, fmt.Errorf("failed to create secret value")
	}

	value := &Value{
		cValue: cValue,
	}

	// Set up finalizer to free C memory when Go object is garbage collected
	runtime.SetFinalizer(value, (*Value).free)

	return value, nil
}

// NewValueFromBytes creates a new secret value from byte slice data.
// This is useful for binary secrets like API keys or certificates.
//
// Example:
//
//	// Create from binary data
//	secretData := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f} // "Hello" in bytes
//	value, err := NewValueFromBytes(secretData, "application/octet-stream")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer value.Unref()
func NewValueFromBytes(data []byte, contentType string) (*Value, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	var cContentType *C.gchar
	if contentType != "" {
		cContentType = C.CString(contentType)
		defer C.free(unsafe.Pointer(cContentType))
	}

	// Convert Go slice to C memory
	cData := (*C.gchar)(unsafe.Pointer(&data[0]))
	cLength := C.gssize(len(data))

	cValue := C.secret_value_new(cData, cLength, cContentType)
	if cValue == nil {
		return nil, fmt.Errorf("failed to create secret value from bytes")
	}

	value := &Value{
		cValue: cValue,
	}

	// Set up finalizer to free C memory when Go object is garbage collected
	runtime.SetFinalizer(value, (*Value).free)

	return value, nil
}

// Get returns the secret value as a byte slice with its actual length.
// This provides access to the raw bytes of the secret.
//
// Example:
//
//	data, length, err := value.Get()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	secret := string(data[:length])
func (v *Value) Get() ([]byte, int, error) {
	if v.cValue == nil {
		return nil, 0, fmt.Errorf("value is nil")
	}

	var cLength C.gsize
	cData := C.secret_value_get(v.cValue, &cLength)
	if cData == nil {
		return nil, 0, fmt.Errorf("failed to get secret data")
	}

	// Create a copy of the data in Go memory
	data := make([]byte, cLength)
	if cLength > 0 {
		copy(data, (*[1 << 30]byte)(unsafe.Pointer(cData))[:cLength:cLength])
	}

	return data, int(cLength), nil
}

// GetText returns the secret value as a text string.
// This assumes the secret is UTF-8 encoded text.
//
// Example:
//
//	secret, err := value.GetText()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Secret:", secret)
func (v *Value) GetText() (string, error) {
	if v.cValue == nil {
		return "", fmt.Errorf("value is nil")
	}

	cText := C.secret_value_get_text(v.cValue)
	if cText == nil {
		return "", fmt.Errorf("failed to get secret as text")
	}
	// Note: Do NOT free cText as it points to internal data
	return C.GoString(cText), nil
}

// GetContentType returns the MIME content type of the secret value.
// Common content types include:
//   - "text/plain" for plain text secrets
//   - "application/octet-stream" for binary data
//   - "application/json" for JSON data
//
// Example:
//
//	contentType, err := value.GetContentType()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Content Type:", contentType)
func (v *Value) GetContentType() (string, error) {
	if v.cValue == nil {
		return "", fmt.Errorf("value is nil")
	}

	cContentType := C.secret_value_get_content_type(v.cValue)
	if cContentType == nil {
		return "", fmt.Errorf("failed to get content type")
	}
	// Note: Do NOT free cContentType as it points to internal data
	return C.GoString(cContentType), nil
}

// Ref increments the reference count on the value.
// This is useful when you need to keep the value alive beyond the current scope.
//
// Example:
//
//	// Get a referenced copy
//	refValue := value.Ref()
//	// Original value can be freed, refValue remains valid
//	refValue.Unref() // Don't forget to unref the copy
func (v *Value) Ref() *Value {
	if v.cValue == nil {
		return nil
	}
	C.secret_value_ref(v.cValue)
	return v
}

// Unref decrements the reference count on the value.
// When the reference count reaches zero, the value is freed and underlying
// C memory is released.
//
// Example:
//
//	value, err := NewValue("secret", -1, "text/plain")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer value.Unref()
func (v *Value) Unref() {
	if v.cValue != nil {
		C.secret_value_unref(C.gpointer(v.cValue))
	}
}

// ToPassword converts the value to a password string and returns it,
// releasing the underlying value resources.
// This is useful when you want to extract the password and free the value
// in one operation.
//
// Example:
//
//	password := value.ToPassword()
//	// value is now invalid, do not use it further
func (v *Value) ToPassword() string {
	if v.cValue == nil {
		return ""
	}

	var cLength C.gsize
	cPassword := C.secret_value_unref_to_password(v.cValue, &cLength)
	
	// Clear the C pointer before setting finalizer to avoid double-free
	v.cValue = nil
	
	// Convert to Go string
	if cPassword == nil {
		return ""
	}
	defer C.secret_password_free(cPassword)

	password := C.GoStringN(cPassword, C.int(cLength))
	return password
}

// free is called by the finalizer to clean up C resources
func (v *Value) free() {
	v.Unref()
	v.cValue = nil
}

// String returns a string representation of the value for debugging.
// Note: This does NOT expose the actual secret content for security reasons.
func (v *Value) String() string {
	if v.cValue == nil {
		return "Value{nil}"
	}

	contentType, err := v.GetContentType()
	if err != nil {
		contentType = "unknown"
	}

	return fmt.Sprintf("Value{content_type=%q, length=%d}", 
		contentType, v.Len())
}

// Len returns the length of the secret data in bytes.
func (v *Value) Len() int {
	if v.cValue == nil {
		return 0
	}

	var cLength C.gsize
	C.secret_value_get(v.cValue, &cLength)
	return int(cLength)
}
