// +kubebuilder:object:generate=true
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterConnectionSpec defines the desired state of ClusterConnection
type ClusterConnectionSpec struct {
	// DisplayName is a human-friendly name for the cluster
	DisplayName string `json:"displayName,omitempty"`

	// Endpoint is the API server endpoint of the target cluster
	Endpoint string `json:"endpoint"`

	// CredentialsRef references the secret containing cluster credentials
	CredentialsRef CredentialsReference `json:"credentialsRef"`

	// Labels for cluster categorization
	Labels map[string]string `json:"labels,omitempty"`

	// Monitoring configuration
	Monitoring MonitoringConfig `json:"monitoring,omitempty"`
}

// CredentialsReference references a secret containing credentials
type CredentialsReference struct {
	// Name of the secret
	Name string `json:"name"`

	// Namespace of the secret (defaults to same namespace as ClusterConnection)
	Namespace string `json:"namespace,omitempty"`
}

// MonitoringConfig defines monitoring settings
type MonitoringConfig struct {
	// Reconciliation interval in seconds (minimum 30, default 30)
	Interval int32 `json:"interval,omitempty"`

	// Connection timeout in seconds (minimum 5, default 10)
	Timeout int32 `json:"timeout,omitempty"`
}

// ClusterConnectionStatus defines the observed state of ClusterConnection
type ClusterConnectionStatus struct {
	// Phase indicates the connection status
	Phase string `json:"phase,omitempty"`

	// LastSyncTime is the timestamp of the last successful sync
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// Health indicates the cluster health
	Health string `json:"health,omitempty"`

	// Message provides additional information about the status
	Message string `json:"message,omitempty"`

	// Nodes is the number of nodes in the cluster
	Nodes int `json:"nodes,omitempty"`

	// Namespaces is the number of namespaces in the cluster
	Namespaces int `json:"namespaces,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=cc
// +kubebuilder:printcolumn:name="Display Name",type="string",JSONPath=".spec.displayName"
// +kubebuilder:printcolumn:name="Endpoint",type="string",JSONPath=".spec.endpoint"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Health",type="string",JSONPath=".status.health"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ClusterConnection is the Schema for the clusterconnections API
type ClusterConnection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterConnectionSpec   `json:"spec,omitempty"`
	Status ClusterConnectionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterConnectionList contains a list of ClusterConnection
type ClusterConnectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterConnection `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterConnection{}, &ClusterConnectionList{})
}
