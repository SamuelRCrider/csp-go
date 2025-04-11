# CSP-Go Deployment Guide

This document outlines the steps to package and deploy the Context Security Protocol (CSP) Go SDK.

## Prerequisites

- Go 1.19 or higher
- Git
- GitHub account
- Access to your organization's GitHub repository

## Packaging Steps

1. **Update Module Path**

   Ensure your `go.mod` file uses the correct GitHub repository path:

   ```go
   module github.com/your-org/csp_go
   ```

2. **Version Your Package**

   Create a semantic version tag:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. **Test Before Release**

   Run comprehensive tests:

   ```bash
   go test -v ./...
   ```

4. **Documentation**

   - Ensure README.md is up-to-date
   - Complete API documentation in code
   - Verify examples in the `/examples` directory work

## Distribution Options

### 1. Go Module (Recommended)

Users can add your SDK to their project using:

```bash
go get github.com/your-org/csp_go@v0.1.0
```

### 2. Binary Releases (Optional)

For command-line tools built with your SDK:

1. Build binaries for multiple platforms:

   ```bash
   GOOS=linux GOARCH=amd64 go build -o bin/csp-linux-amd64 ./cmd
   GOOS=darwin GOARCH=amd64 go build -o bin/csp-macos-amd64 ./cmd
   GOOS=windows GOARCH=amd64 go build -o bin/csp-windows-amd64.exe ./cmd
   ```

2. Create a GitHub release with these binaries attached

## Private Distribution

For enterprise customers requiring private access:

1. **Private Go Module**:

   - Host on private GitHub repository
   - Users need appropriate access and must configure Git credentials

2. **Internal Go Module Proxy**:

   - Set up an internal Go proxy (like Athens)
   - Configure client environments to use your proxy

## Integration Guide

Provide the following instructions to users:

1. Add the dependency:

   ```bash
   go get github.com/your-org/csp_go@v0.1.0
   ```

2. Import in code:

   ```go
   import "github.com/your-org/csp_go"
   ```

3. Set required environment variables:

   ```bash
   export CSP_ENCRYPTION_KEY="your-32-byte-key-here-for-aes-security"
   ```

## Maintenance

1. Regularly update dependencies
2. Address security vulnerabilities promptly
3. Maintain semantic versioning for all releases
4. Document breaking changes clearly

## Support

Include information on how users can get support:

- GitHub Issues for bug reports
- Support email for enterprise customers
- Documentation resources
