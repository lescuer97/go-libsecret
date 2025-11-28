# go-libsecret

A Go library that provides CGO bindings to the libsecret C library for secure secret storage and retrieval on Linux systems.

[![Go Reference](https://pkg.go.dev/badge/github.com/yourorg/go-libsecret.svg)](https://pkg.go.dev/github.com/yourorg/go-libsecret)
[![License](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](LICENSE)

## Overview

`go-libsecret` is a Go wrapper around [libsecret](https://gitlab.gnome.org/GNOME/libsecret), a GObject-based library for storing and retrieving passwords and other secrets. It provides a type-safe, idiomatic Go API while maintaining full compatibility with the underlying C library.

**libsecret** stores secrets using two mechanisms:
- **Secret Service**: Via the freedesktop Secret Service DBus API (used by GNOME Keyring, KWallet, etc.)
- **File Backend**: Encrypted file storage when the Secret Service is unavailable

## Features

✅ **Core Types Implemented (Phase 1)**
- ✅ `Schema` - Define the structure of secret items and their attributes
- ✅ `Value` - Represent secret values with proper memory management
- ✅ `Attributes` - Key-value pairs for identifying and looking up secrets
- ✅ Schema attribute types (String, Integer, Boolean)
- ✅ Schema flags (None, DontMatchName)

🚧 **Coming Soon (Phase 2)**
- Password storage and retrieval (simple API)
- Collection management
- Item operations
- Service integration

## Requirements

### System Dependencies

You must have libsecret development files installed:

```bash
# Debian/Ubuntu
sudo apt-get install libsecret-1-dev

# Fedora/RHEL
sudo dnf install libsecret-devel

# Arch Linux
sudo pacman -S libsecret

# macOS (via Homebrew)
brew install libsecret
```

### Go Requirements

- Go 1.19 or higher
- CGO enabled (required for C bindings)

## Installation

```bash
go get github.com/yourorg/go-libsecret
```

## Quick Start

### 1. Define a Schema

Schemas define the structure of your secrets and the attributes used to identify them:

```go
package main

import (
    "fmt"
    "log"
    
    secret "github.com/yourorg/go-libsecret"
)

func main() {
    // Define a schema for web passwords
    schema, err := secret.NewSchema(
        "org.example.WebPassword",
        secret.SchemaFlagsNone,
        map[string]secret.SchemaAttributeType{
            "username": secret.SchemaAttributeString,
            "url":      secret.SchemaAttributeString,
            "port":     secret.SchemaAttributeInteger,
            "ssl":      secret.SchemaAttributeBoolean,
        },
    )
    if err != nil {
        log.Fatal(err)
    }
    defer schema.Unref()
    
    fmt.Printf("Schema created: %s\n", schema.Name())
}
```

### 2. Create Secret Values

Store passwords and other sensitive data:

```go
// Create a text secret
password, err := secret.NewValue("my-secret-password", -1, "text/plain")
if err != nil {
    log.Fatal(err)
}
defer password.Unref()

// Retrieve the secret as text
secretText, err := password.GetText()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Password length: %d\n", len(secretText))

// Create a binary secret
apiKey := []byte{0x4b, 0x45, 0x59, 0x31, 0x32, 0x33}
keyValue, err := secret.NewValueFromBytes(apiKey, "application/octet-stream")
if err != nil {
    log.Fatal(err)
}
defer keyValue.Unref()
```

### 3. Build Attributes

Attributes are metadata used to lookup secrets (not encrypted):

```go
// Method 1: Using AttributesFromMap
attrs, err := secret.AttributesFromMap(map[string]string{
    "username": "john.doe",
    "url":      "https://example.com",
    "port":     "8080",
    "ssl":      "true",
})
if err != nil {
    log.Fatal(err)
}
defer attrs.Free()

// Method 2: Using BuildAttributes (variadic)
attrs2, err := secret.BuildAttributes(
    "username", "john.doe",
    "url", "https://example.com",
    "port", 8080,     // Automatically converted to string
    "ssl", true,      // Automatically converted to "true"
)
if err != nil {
    log.Fatal(err)
}
defer attrs2.Free()

// Method 3: Using AttributeBuilder (fluent API)
attrs3, err := secret.NewAttributeBuilder().
    WithString("username", "john.doe").
    WithString("url", "https://example.com").
    WithInteger("port", 8080).
    WithBoolean("ssl", true).
    Build()
if err != nil {
    log.Fatal(err)
}
defer attrs3.Free()
```

### 4. Validate Attributes Against Schema

```go
// Validate that attributes match the schema
err = secret.ValidateAttributesAgainstSchema(schema, attrs)
if err != nil {
    log.Fatalf("Validation failed: %v", err)
}
```

## API Documentation

### Schema

The `Schema` type defines the structure of secret items and their attributes:

```go
type Schema struct {
    // ... internal fields
}

// Create a new schema
func NewSchema(name string, flags SchemaFlags, 
               attributes map[string]SchemaAttributeType) (*Schema, error)

// Methods
func (s *Schema) Name() string
func (s *Schema) Flags() SchemaFlags
func (s *Schema) Attributes() map[string]SchemaAttributeType
func (s *Schema) Ref() *Schema
func (s *Schema) Unref()
```

### SchemaAttributeType

Defines the type of attributes in a schema:

```go
const (
    SchemaAttributeString  SchemaAttributeType // String attribute
    SchemaAttributeInteger SchemaAttributeType // Integer attribute (stored as string)
    SchemaAttributeBoolean SchemaAttributeType // Boolean attribute ("true"/"false")
)
```

### SchemaFlags

Flags that control schema behavior:

```go
const (
    SchemaFlagsNone           SchemaFlags // No special flags
    SchemaFlagsDontMatchName  SchemaFlags // Don't match schema name (for migration)
)
```

### Value

Represents a secret value with memory management:

```go
type Value struct {
    // ... internal fields
}

// Constructors
func NewValue(secret string, length int, contentType string) (*Value, error)
func NewValueFromBytes(data []byte, contentType string) (*Value, error)

// Methods
func (v *Value) Get() ([]byte, int, error)
func (v *Value) GetText() (string, error)
func (v *Value) GetContentType() (string, error)
func (v *Value) Len() int
func (v *Value) Ref() *Value
func (v *Value) Unref()
func (v *Value) ToPassword() string
```

### Attributes

Key-value pairs for identifying secrets:

```go
type Attributes struct {
    // ... internal fields
}

// Constructors
func NewAttributes() *Attributes
func AttributesFromMap(values map[string]string) (*Attributes, error)
func BuildAttributes(args ...interface{}) (*Attributes, error)

// Methods
func (a *Attributes) Set(key, value string) error
func (a *Attributes) Get(key string) string
func (a *Attributes) Has(key string) bool
func (a *Attributes) Delete(key string) bool
func (a *Attributes) Keys() []string
func (a *Attributes) Len() int
func (a *Attributes) ToMap() map[string]string
func (a *Attributes) Clone() (*Attributes, error)
func (a *Attributes) Free()
```

## Memory Management

The library handles C memory automatically using Go finalizers, but for optimal performance you should explicitly call cleanup methods:

```go
// Always use defer to ensure cleanup
schema, err := secret.NewSchema(...)
if err != nil {
    log.Fatal(err)
}
defer schema.Unref()  // Clean up C resources

value, err := secret.NewValue(...)
if err != nil {
    log.Fatal(err)
}
defer value.Unref()  // Clean up C resources

attrs := secret.NewAttributes()
defer attrs.Free()  // Clean up C resources
```

## Best Practices

### 1. Schema Naming

Use reverse-domain notation for schema names:

```go
schema, _ := secret.NewSchema(
    "com.example.myapp.DatabaseCredentials",  // Good
    secret.SchemaFlagsNone,
    attributes,
)
```

### 2. Attribute Security

**IMPORTANT**: Attributes are NOT encrypted. Don't store sensitive information in attributes:

```go
// ❌ BAD - Password in attributes
attrs.Set("password", "my-secret")  // Don't do this!

// ✅ GOOD - Only metadata in attributes
attrs.Set("username", "john")
attrs.Set("service", "database")
```

### 3. Type Safety

Use typed methods for better type safety:

```go
// ✅ GOOD - Type-safe builder
attrs, _ := secret.NewAttributeBuilder().
    WithString("username", "john").
    WithInteger("port", 5432).
    WithBoolean("ssl", true).
    Build()

// ⚠️ OK but less type-safe
attrs2, _ := secret.BuildAttributes(
    "username", "john",
    "port", 5432,
    "ssl", true,
)
```

### 4. Error Handling

Always check for errors:

```go
schema, err := secret.NewSchema(name, flags, attributes)
if err != nil {
    return fmt.Errorf("failed to create schema: %w", err)
}
defer schema.Unref()
```

## Examples

See the [examples_test.go](examples_test.go) file for complete working examples.

## Development Status

This library is currently in **Phase 1** of development:

- ✅ Phase 1: Foundation and Core Types (Complete)
  - Schema definition and validation
  - Secret value handling
  - Attribute management

- 🚧 Phase 2: Password Operations (Planned)
  - Store passwords
  - Lookup passwords
  - Remove passwords
  - Simple password API

- 🚧 Phase 3: Advanced Features (Planned)
  - Collection management
  - Item operations
  - Service integration

## Testing

```bash
# Run tests
go test -v ./...

# Run tests with CGO enabled
CGO_ENABLED=1 go test -v ./...

# Run examples
go test -v -run Example
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## License

This library is licensed under the LGPL-2.1 license, matching the libsecret library it wraps.

## Credits

- **libsecret**: The underlying C library by GNOME
- **Contributors**: See [CONTRIBUTORS.md](CONTRIBUTORS.md)

## References

- [libsecret documentation](https://gnome.pages.gitlab.gnome.org/libsecret/)
- [Secret Service specification](https://specifications.freedesktop.org/secret-service-spec/)
- [libsecret GitLab repository](https://gitlab.gnome.org/GNOME/libsecret)

## Support

For issues and questions:
- 🐛 [Report bugs](https://github.com/yourorg/go-libsecret/issues)
- 💬 [Discussions](https://github.com/yourorg/go-libsecret/discussions)
- 📖 [Documentation](https://pkg.go.dev/github.com/yourorg/go-libsecret)
