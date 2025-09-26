package registry

import (
    "context"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
    
    "github.com/sirupsen/logrus"
)

// DockerV2Client implements a Docker Registry v2 API client for health checking
type DockerV2Client struct {
    endpoint      string
    httpClient    *http.Client
    authHeader    string
    logger        *logrus.Entry
}

// HealthCheckResult contains the results of a registry health check
type HealthCheckResult struct {
    Available       bool              `json:"available"`
    ResponseTime    int64             `json:"response_time_ms"`
    Version         string            `json:"version,omitempty"`
    RepositoryCount int               `json:"repository_count,omitempty"`
    Features        map[string]bool   `json:"features,omitempty"`
    Repositories    []string          `json:"repositories,omitempty"`
    Error           string            `json:"error,omitempty"`
}

// CatalogResponse represents the Docker v2 catalog API response
type CatalogResponse struct {
    Repositories []string `json:"repositories"`
}

// NewDockerV2Client creates a new Docker Registry v2 client
func NewDockerV2Client(endpoint string, username, password string, insecure bool, skipTLSVerify bool) *DockerV2Client {
    // Ensure endpoint has protocol
    if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
        endpoint = "https://" + endpoint
    }
    
    // Remove trailing slash
    endpoint = strings.TrimSuffix(endpoint, "/")
    
    // Configure HTTP client
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: skipTLSVerify,
        },
        MaxIdleConns:        10,
        IdleConnTimeout:     30 * time.Second,
        DisableCompression:  true,
    }
    
    httpClient := &http.Client{
        Transport: transport,
        Timeout:   10 * time.Second,
    }
    
    client := &DockerV2Client{
        endpoint:   endpoint,
        httpClient: httpClient,
        logger:     logrus.WithField("registry", endpoint),
    }
    
    // Set up authentication if provided
    if username != "" && password != "" {
        auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
        client.authHeader = fmt.Sprintf("Basic %s", auth)
    }
    
    return client
}

// HealthCheck performs a health check on the registry
func (c *DockerV2Client) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
    startTime := time.Now()
    result := &HealthCheckResult{
        Features: make(map[string]bool),
    }
    
    // Check /v2/ endpoint (required for Docker v2 API)
    v2URL := fmt.Sprintf("%s/v2/", c.endpoint)
    req, err := http.NewRequestWithContext(ctx, "GET", v2URL, nil)
    if err != nil {
        result.Error = fmt.Sprintf("failed to create request: %v", err)
        return result, err
    }
    
    if c.authHeader != "" {
        req.Header.Set("Authorization", c.authHeader)
    }
    req.Header.Set("Accept", "application/json")
    
    resp, err := c.httpClient.Do(req)
    responseTime := time.Since(startTime).Milliseconds()
    result.ResponseTime = responseTime
    
    if err != nil {
        result.Available = false
        result.Error = fmt.Sprintf("request failed: %v", err)
        c.logger.WithError(err).Error("Health check failed")
        return result, err
    }
    defer resp.Body.Close()
    
    // Check status code
    switch resp.StatusCode {
    case http.StatusOK:
        result.Available = true
        c.logger.Debug("Registry is available")
    case http.StatusUnauthorized:
        // Registry requires authentication but is available
        result.Available = true
        result.Features["requires_auth"] = true
        c.logger.Debug("Registry requires authentication")
    default:
        result.Available = false
        result.Error = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
        c.logger.Warnf("Unexpected status code: %d", resp.StatusCode)
        return result, nil
    }
    
    // Try to detect registry type and version from headers
    c.detectRegistryInfo(resp, result)
    
    return result, nil
}

// CheckCatalog checks the registry catalog endpoint
func (c *DockerV2Client) CheckCatalog(ctx context.Context, maxEntries int) (*CatalogResponse, error) {
    catalogURL := fmt.Sprintf("%s/v2/_catalog", c.endpoint)
    if maxEntries > 0 {
        catalogURL = fmt.Sprintf("%s?n=%d", catalogURL, maxEntries)
    }
    
    req, err := http.NewRequestWithContext(ctx, "GET", catalogURL, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create catalog request: %w", err)
    }
    
    if c.authHeader != "" {
        req.Header.Set("Authorization", c.authHeader)
    }
    req.Header.Set("Accept", "application/json")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("catalog request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("catalog request returned %d: %s", resp.StatusCode, string(body))
    }
    
    var catalog CatalogResponse
    if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
        return nil, fmt.Errorf("failed to decode catalog response: %w", err)
    }
    
    return &catalog, nil
}

// CheckRepository checks if a specific repository exists and is accessible
func (c *DockerV2Client) CheckRepository(ctx context.Context, repository string) (bool, error) {
    // Check repository tags to verify it exists
    tagsURL := fmt.Sprintf("%s/v2/%s/tags/list", c.endpoint, repository)
    
    req, err := http.NewRequestWithContext(ctx, "GET", tagsURL, nil)
    if err != nil {
        return false, fmt.Errorf("failed to create tags request: %w", err)
    }
    
    if c.authHeader != "" {
        req.Header.Set("Authorization", c.authHeader)
    }
    req.Header.Set("Accept", "application/json")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()
    
    return resp.StatusCode == http.StatusOK, nil
}

// detectRegistryInfo attempts to detect registry type and version from response headers
func (c *DockerV2Client) detectRegistryInfo(resp *http.Response, result *HealthCheckResult) {
    // Check for Docker-Distribution-Api-Version header (standard for all Docker v2 registries)
    if apiVersion := resp.Header.Get("Docker-Distribution-Api-Version"); apiVersion != "" {
        result.Version = apiVersion
        result.Features["docker_v2_api"] = true
    }
    
    // Some registries advertise themselves via headers (optional detection)
    // This is purely informational and doesn't change behavior
    if serverHeader := resp.Header.Get("Server"); serverHeader != "" {
        serverLower := strings.ToLower(serverHeader)
        
        // These are just hints about what registry software is being used
        if strings.Contains(serverLower, "harbor") {
            result.Features["harbor_detected"] = true
        } else if strings.Contains(serverLower, "artifactory") {
            result.Features["artifactory_detected"] = true
        } else if strings.Contains(serverLower, "nexus") {
            result.Features["nexus_detected"] = true
        }
    }
    
    // Check for standard Docker v2 features
    if resp.Header.Get("Docker-Content-Digest") != "" {
        result.Features["content_digest"] = true
    }
    
    // Check for pagination support (part of Docker v2 spec)
    if resp.Header.Get("Link") != "" {
        result.Features["pagination"] = true
    }
}

// ExtendedHealthCheck performs a comprehensive health check including catalog
func (c *DockerV2Client) ExtendedHealthCheck(ctx context.Context, checkCatalog bool, maxCatalogEntries int) (*HealthCheckResult, error) {
    // Perform basic health check
    result, err := c.HealthCheck(ctx)
    if err != nil {
        return result, err
    }
    
    if !result.Available {
        return result, nil
    }
    
    // Check catalog if requested and registry is available
    if checkCatalog {
        catalog, err := c.CheckCatalog(ctx, maxCatalogEntries)
        if err != nil {
            c.logger.WithError(err).Warn("Failed to check catalog")
            result.Features["catalog_accessible"] = false
        } else {
            result.Features["catalog_accessible"] = true
            result.RepositoryCount = len(catalog.Repositories)
            
            // Include repository list if not too large
            if len(catalog.Repositories) <= 20 {
                result.Repositories = catalog.Repositories
            }
        }
    }
    
    return result, nil
}

// TestAuthentication tests if the provided credentials are valid
func (c *DockerV2Client) TestAuthentication(ctx context.Context) error {
    // Try to access the catalog endpoint which typically requires auth
    _, err := c.CheckCatalog(ctx, 1)
    return err
}

// ParseEndpoint validates and normalizes a registry endpoint
func ParseEndpoint(endpoint string) (*url.URL, error) {
    // Add protocol if missing
    if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
        endpoint = "https://" + endpoint
    }
    
    u, err := url.Parse(endpoint)
    if err != nil {
        return nil, fmt.Errorf("invalid endpoint URL: %w", err)
    }
    
    // Validate the URL
    if u.Scheme != "http" && u.Scheme != "https" {
        return nil, fmt.Errorf("unsupported protocol: %s", u.Scheme)
    }
    
    if u.Host == "" {
        return nil, fmt.Errorf("missing host in URL")
    }
    
    return u, nil
}
