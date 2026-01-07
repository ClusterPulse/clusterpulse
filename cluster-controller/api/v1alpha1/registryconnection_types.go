// cluster-controller/api/v1alpha1/registryconnection_types.go
// +kubebuilder:object:generate=true
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RegistryConnectionSpec defines the desired state of RegistryConnection
type RegistryConnectionSpec struct {
	// DisplayName is a human-friendly name for the registry
	DisplayName string `json:"displayName,omitempty"`

	// Endpoint is the registry endpoint (e.g., https://registry.example.com)
	Endpoint string `json:"endpoint"`

	// Type is optional and purely informational (all registries use Docker v2 API)
	// Examples: "dockerhub", "harbor", "ecr", "gcr", "artifactory"
	// Can be left empty or any string for documentation purposes
	Type string `json:"type,omitempty"`

	// CredentialsRef references the secret containing registry credentials (optional)
	// Secret should contain "username" and "password" fields
	CredentialsRef *CredentialsReference `json:"credentialsRef,omitempty"`

	// Insecure allows connecting to registries with self-signed certificates
	Insecure bool `json:"insecure,omitempty"`

	// SkipTLSVerify skips TLS certificate verification
	SkipTLSVerify bool `json:"skipTLSVerify,omitempty"`

	// Monitoring configuration
	Monitoring RegistryMonitoringConfig `json:"monitoring,omitempty"`

	// Labels for registry categorization
	Labels map[string]string `json:"labels,omitempty"`

	// HealthCheckPaths to verify (defaults to ["/v2/"])
	HealthCheckPaths []string `json:"healthCheckPaths,omitempty"`
}

// RegistryMonitoringConfig defines monitoring settings for registry
type RegistryMonitoringConfig struct {
	// Interval in seconds between health checks (minimum 30, default 60)
	Interval int32 `json:"interval,omitempty"`

	// Timeout in seconds for health check requests (minimum 5, default 10)
	Timeout int32 `json:"timeout,omitempty"`

	// CheckCatalog enables checking /v2/_catalog endpoint (requires appropriate permissions)
	CheckCatalog bool `json:"checkCatalog,omitempty"`

	// MaxCatalogEntries limits the number of catalog entries to fetch (default 100)
	MaxCatalogEntries int32 `json:"maxCatalogEntries,omitempty"`
}

// RegistryConnectionStatus defines the observed state of RegistryConnection
type RegistryConnectionStatus struct {
	// Phase indicates the connection status (Connecting, Connected, Error, Unknown)
	Phase string `json:"phase,omitempty"`

	// Health indicates registry health (healthy, degraded, unhealthy, unknown)
	Health string `json:"health,omitempty"`

	// Available indicates if the registry is reachable
	Available bool `json:"available"`

	// LastCheckTime is the timestamp of the last health check
	LastCheckTime *metav1.Time `json:"lastCheckTime,omitempty"`

	// ResponseTime is the last health check response time in milliseconds
	ResponseTime int64 `json:"responseTime,omitempty"`

	// Message provides additional information about the status
	Message string `json:"message,omitempty"`

	// RepositoryCount is the number of repositories (if catalog check is enabled)
	RepositoryCount int `json:"repositoryCount,omitempty"`

	// Version is the registry version (if detectable)
	Version string `json:"version,omitempty"`

	// Features detected from the registry
	Features map[string]bool `json:"features,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=rc;regcon
// +kubebuilder:printcolumn:name="Display Name",type="string",JSONPath=".spec.displayName"
// +kubebuilder:printcolumn:name="Endpoint",type="string",JSONPath=".spec.endpoint"
// +kubebuilder:printcolumn:name="Type",type="string",JSONPath=".spec.type"
// +kubebuilder:printcolumn:name="Available",type="boolean",JSONPath=".status.available"
// +kubebuilder:printcolumn:name="Health",type="string",JSONPath=".status.health"
// +kubebuilder:printcolumn:name="Response Time",type="integer",JSONPath=".status.responseTime"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// RegistryConnection is the Schema for the registryconnections API
type RegistryConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RegistryConnectionSpec   `json:"spec,omitempty"`
	Status RegistryConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RegistryConnectionList contains a list of RegistryConnection
type RegistryConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RegistryConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RegistryConnection{}, &RegistryConnectionList{})
}
