# Unit Tests

This directory contains unit tests for the Provenance Graph SBOM Linker.

## Overview

Unit tests focus on testing individual components, functions, and methods in isolation. They should be fast, reliable, and independent of external dependencies.

## Structure

```
unit/
├── README.md                 # This file
├── pkg/                     # Tests for pkg/ directory
│   ├── client/             # Client library tests
│   ├── types/              # Type definition tests
│   └── utils/              # Utility function tests
└── internal/               # Tests for internal/ directory
    ├── auth/               # Authentication tests
    ├── database/           # Database layer tests
    ├── handlers/           # HTTP handler tests
    ├── middleware/         # Middleware tests
    ├── services/           # Business logic tests
    └── workers/            # Background worker tests
```

## Test Conventions

### File Naming
- Test files should be named `*_test.go`
- Place test files in the same package as the code being tested
- For internal packages, create corresponding test directories

### Test Function Naming
- Test functions should start with `Test`
- Use descriptive names: `TestServiceName_MethodName_Scenario`
- Examples:
  - `TestProvenanceService_TrackBuild_ValidInput`
  - `TestSBOMParser_Parse_InvalidFormat`

### Test Structure
Use the Arrange-Act-Assert pattern:

```go
func TestExample(t *testing.T) {
    // Arrange
    input := setupTestInput()
    expectedOutput := "expected result"
    
    // Act
    result, err := functionUnderTest(input)
    
    // Assert
    assert.NoError(t, err)
    assert.Equal(t, expectedOutput, result)
}
```

### Table-Driven Tests
For testing multiple scenarios:

```go
func TestValidation(t *testing.T) {
    tests := []struct {
        name    string
        input   Input
        want    Output
        wantErr bool
    }{
        {
            name:    "valid input",
            input:   validInput,
            want:    expectedOutput,
            wantErr: false,
        },
        {
            name:    "invalid input",
            input:   invalidInput,
            want:    Output{},
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := functionUnderTest(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.want, got)
            }
        })
    }
}
```

## Mock Usage

Use generated mocks for external dependencies:

```go
//go:generate mockgen -source=service.go -destination=mocks/service_mock.go

func TestServiceWithMock(t *testing.T) {
    ctrl := gomock.NewController(t)
    defer ctrl.Finish()
    
    mockDB := mocks.NewMockDatabase(ctrl)
    mockDB.EXPECT().Get("key").Return("value", nil)
    
    service := NewService(mockDB)
    result, err := service.GetValue("key")
    
    assert.NoError(t, err)
    assert.Equal(t, "value", result)
}
```

## Test Helpers

Common test helpers are available in the `testutil` package:

```go
func TestWithHelper(t *testing.T) {
    // Create test database
    db := testutil.NewTestDB(t)
    defer db.Close()
    
    // Create test HTTP server
    server := testutil.NewTestServer(t, handler)
    defer server.Close()
    
    // Test implementation
}
```

## Coverage Requirements

- Minimum coverage: 80%
- Critical paths: 95%+
- New code: 90%+

Check coverage with:
```bash
make test-coverage
```

## Running Tests

```bash
# All unit tests
make test-unit

# Specific package
go test ./pkg/client/...

# With coverage
go test -cover ./...

# With race detection
go test -race ./...

# Verbose output
go test -v ./...
```

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Fast Execution**: Unit tests should run quickly (< 100ms each)
3. **Clear Assertions**: Use descriptive error messages
4. **Mock External Dependencies**: Don't depend on external services
5. **Test Edge Cases**: Include boundary conditions and error cases
6. **Maintainable Tests**: Keep tests simple and focused

## Test Data

- Use the `fixtures` directory for test data files
- Create test data programmatically when possible
- Use builders for complex test objects

## Continuous Integration

Unit tests run on every commit and pull request. They must pass before code can be merged.

## Resources

- [Go Testing Package](https://pkg.go.dev/testing)
- [Testify Assert](https://pkg.go.dev/github.com/stretchr/testify/assert)
- [GoMock](https://github.com/golang/mock)
- [Testing Best Practices](https://go.dev/doc/tutorial/add-a-test)