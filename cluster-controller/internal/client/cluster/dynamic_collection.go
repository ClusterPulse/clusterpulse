package cluster

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/clusterpulse/cluster-controller/api/v1alpha1"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/util/jsonpath"
)

// CollectedResource represents a single collected resource instance
type CollectedResource struct {
	Meta   ResourceMeta           `json:"_meta"`
	Fields map[string]interface{} `json:"fields,omitempty"`
}

// ResourceMeta contains standard metadata for all collected resources
type ResourceMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	CreationTimestamp string            `json:"creationTimestamp"`
	CollectedAt       string            `json:"collectedAt"`
}

// CollectionResult contains the results of a dynamic resource collection
type CollectionResult struct {
	Resources        []map[string]interface{} `json:"resources"`
	Truncated        bool                     `json:"truncated"`
	TotalCount       int                      `json:"total_count"`
	CollectionTimeMs int64                    `json:"collection_time_ms"`
	Error            string                   `json:"error,omitempty"`
}

// CollectMonitoredResources collects resources based on a ResourceMonitor spec
func (c *ClusterClient) CollectMonitoredResources(ctx context.Context, monitor *v1alpha1.ResourceMonitor) (*CollectionResult, error) {
	startTime := time.Now()
	log := logrus.WithFields(logrus.Fields{
		"cluster": c.Name,
		"monitor": monitor.Name,
		"kind":    monitor.Spec.Target.Kind,
	})

	c.updateLastUsed()

	result := &CollectionResult{
		Resources: make([]map[string]interface{}, 0),
	}

	// Parse the target API version and kind into a GVR
	gvr, namespaced, err := c.resolveGVR(ctx, monitor.Spec.Target.APIVersion, monitor.Spec.Target.Kind)
	if err != nil {
		result.Error = err.Error()
		result.CollectionTimeMs = time.Since(startTime).Milliseconds()
		return result, err
	}

	log.Debugf("Resolved GVR: %s (namespaced: %v)", gvr.String(), namespaced)

	// Determine which namespaces to query
	namespaces, err := c.getTargetNamespaces(ctx, monitor.Spec.Collection.NamespaceSelector, namespaced)
	if err != nil {
		result.Error = err.Error()
		result.CollectionTimeMs = time.Since(startTime).Milliseconds()
		return result, err
	}

	// Build label selector if specified
	labelSelector := ""
	if monitor.Spec.Collection.ResourceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(monitor.Spec.Collection.ResourceSelector)
		if err != nil {
			log.WithError(err).Warn("Invalid resource selector, ignoring")
		} else {
			labelSelector = selector.String()
		}
	}

	// Collection limits
	perNsLimit := int(monitor.Spec.Collection.Limits.PerNamespace)
	if perNsLimit <= 0 {
		perNsLimit = 100 // sensible default
	}
	totalLimit := int(monitor.Spec.Collection.Limits.PerCluster)
	if totalLimit <= 0 {
		totalLimit = 1000 // sensible default
	}

	// Collect resources
	var allResources []map[string]interface{}
	truncated := false

	for _, ns := range namespaces {
		if len(allResources) >= totalLimit {
			truncated = true
			break
		}

		resources, nsTruncated, err := c.collectFromNamespace(ctx, gvr, ns, namespaced, labelSelector, perNsLimit, monitor)
		if err != nil {
			log.WithError(err).Warnf("Failed to collect from namespace %s", ns)
			continue
		}

		if nsTruncated {
			truncated = true
		}

		// Respect total limit
		remaining := totalLimit - len(allResources)
		if len(resources) > remaining {
			resources = resources[:remaining]
			truncated = true
		}

		allResources = append(allResources, resources...)
	}

	result.Resources = allResources
	result.TotalCount = len(allResources)
	result.Truncated = truncated
	result.CollectionTimeMs = time.Since(startTime).Milliseconds()

	log.Debugf("Collected %d resources in %dms (truncated: %v)", result.TotalCount, result.CollectionTimeMs, truncated)

	return result, nil
}

// resolveGVR converts apiVersion and kind into a GroupVersionResource
func (c *ClusterClient) resolveGVR(ctx context.Context, apiVersion, kind string) (schema.GroupVersionResource, bool, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, false, err
	}

	// Use discovery to find the resource name and scope
	resourceList, err := c.clientset.Discovery().ServerResourcesForGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionResource{}, false, err
	}

	for _, r := range resourceList.APIResources {
		if r.Kind == kind {
			// Skip subresources
			if strings.Contains(r.Name, "/") {
				continue
			}

			gvr := schema.GroupVersionResource{
				Group:    gv.Group,
				Version:  gv.Version,
				Resource: r.Name,
			}
			namespaced := r.Namespaced
			return gvr, namespaced, nil
		}
	}

	return schema.GroupVersionResource{}, false, fmt.Errorf("resource %s not found in %s", kind, apiVersion)
}

// getTargetNamespaces determines which namespaces to collect from
func (c *ClusterClient) getTargetNamespaces(ctx context.Context, selector *v1alpha1.NamespaceSelector, namespaced bool) ([]string, error) {
	// Cluster-scoped resources don't need namespace filtering
	if !namespaced {
		return []string{""}, nil
	}

	// Get all namespaces first
	nsList, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, ns := range nsList.Items {
		// Apply label selector if specified
		if selector != nil && len(selector.MatchLabels) > 0 {
			match := true
			for k, v := range selector.MatchLabels {
				if ns.Labels[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		// Apply include/exclude patterns
		if selector != nil && !matchesNamespaceSelector(ns.Name, selector) {
			continue
		}

		namespaces = append(namespaces, ns.Name)
	}

	// If no selector provided or nothing matched include patterns, return all
	if len(namespaces) == 0 && (selector == nil || len(selector.Include) == 0) {
		for _, ns := range nsList.Items {
			if selector != nil && !matchesNamespaceSelector(ns.Name, selector) {
				continue
			}
			namespaces = append(namespaces, ns.Name)
		}
	}

	return namespaces, nil
}

// matchesNamespaceSelector checks if a namespace matches the selector patterns
func matchesNamespaceSelector(namespace string, selector *v1alpha1.NamespaceSelector) bool {
	if selector == nil {
		return true
	}

	// Check exclude patterns first (they take precedence)
	for _, pattern := range selector.Exclude {
		if matchGlob(pattern, namespace) {
			return false
		}
	}

	// If no include patterns, include all (that weren't excluded)
	if len(selector.Include) == 0 {
		return true
	}

	// Check include patterns
	for _, pattern := range selector.Include {
		if matchGlob(pattern, namespace) {
			return true
		}
	}

	return false
}

// matchGlob performs basic glob matching
func matchGlob(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		// Fall back to prefix matching if pattern is invalid
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}
	return matched
}

// collectFromNamespace collects resources from a single namespace
func (c *ClusterClient) collectFromNamespace(
	ctx context.Context,
	gvr schema.GroupVersionResource,
	namespace string,
	namespaced bool,
	labelSelector string,
	limit int,
	monitor *v1alpha1.ResourceMonitor,
) ([]map[string]interface{}, bool, error) {
	opts := metav1.ListOptions{
		LabelSelector: labelSelector,
		Limit:         int64(limit),
	}

	var list *unstructured.UnstructuredList
	var err error

	if namespaced && namespace != "" {
		list, err = c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, opts)
	} else {
		list, err = c.dynamicClient.Resource(gvr).List(ctx, opts)
	}

	if err != nil {
		return nil, false, err
	}

	truncated := list.GetContinue() != ""
	resources := make([]map[string]interface{}, 0, len(list.Items))
	collectedAt := time.Now().UTC().Format(time.RFC3339)

	for _, item := range list.Items {
		resource := c.extractResourceData(&item, monitor, collectedAt)
		resources = append(resources, resource)
	}

	return resources, truncated, nil
}

// extractResourceData extracts the configured fields from a resource
func (c *ClusterClient) extractResourceData(
	item *unstructured.Unstructured,
	monitor *v1alpha1.ResourceMonitor,
	collectedAt string,
) map[string]interface{} {
	result := make(map[string]interface{})

	// Always include standard metadata
	meta := map[string]interface{}{
		"name":              item.GetName(),
		"namespace":         item.GetNamespace(),
		"uid":               string(item.GetUID()),
		"creationTimestamp": item.GetCreationTimestamp().Format(time.RFC3339),
		"collectedAt":       collectedAt,
	}

	// Include labels (always, but ensure not nil)
	lbls := item.GetLabels()
	if lbls == nil {
		lbls = map[string]string{}
	}
	meta["labels"] = lbls

	// Include annotations only if configured
	if monitor.Spec.Schema.IncludeAnnotations {
		annotations := item.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		meta["annotations"] = annotations
	}

	result["_meta"] = meta

	// Extract custom fields
	for _, field := range monitor.Spec.Schema.Fields {
		value := extractField(item.Object, field)
		result[field.Name] = value
	}

	return result
}

// extractField extracts a single field value using JSONPath
func extractField(obj map[string]interface{}, field v1alpha1.FieldDefinition) interface{} {
	// Parse and execute JSONPath
	path := field.Path

	// Handle JSONPath expressions
	if strings.HasPrefix(path, "{") && strings.HasSuffix(path, "}") {
		jp := jsonpath.New(field.Name)
		// JSONPath library expects the path without the outer braces for some operations
		// but we need to parse the full expression
		if err := jp.Parse(path); err != nil {
			logrus.WithError(err).Debugf("Invalid JSONPath: %s", path)
			return applyDefault(field.Default, field.Type)
		}

		results, err := jp.FindResults(obj)
		if err != nil || len(results) == 0 || len(results[0]) == 0 {
			return applyDefault(field.Default, field.Type)
		}

		value := results[0][0].Interface()
		return applyTransform(value, field.Transform, field.Type)
	}

	return applyDefault(field.Default, field.Type)
}

// applyTransform applies a transformation to the extracted value
func applyTransform(value interface{}, transform, fieldType string) interface{} {
	if transform == "" {
		return value
	}

	switch transform {
	case "keys":
		if m, ok := value.(map[string]interface{}); ok {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			return keys
		}
		return []string{}

	case "count":
		switch v := value.(type) {
		case map[string]interface{}:
			return len(v)
		case []interface{}:
			return len(v)
		case string:
			return len(v)
		default:
			return 0
		}

	case "first":
		if arr, ok := value.([]interface{}); ok && len(arr) > 0 {
			return arr[0]
		}
		return nil

	case "last":
		if arr, ok := value.([]interface{}); ok && len(arr) > 0 {
			return arr[len(arr)-1]
		}
		return nil

	case "join":
		if arr, ok := value.([]interface{}); ok {
			strs := make([]string, 0, len(arr))
			for _, v := range arr {
				if s, ok := v.(string); ok {
					strs = append(strs, s)
				}
			}
			return strings.Join(strs, ",")
		}
		return ""

	case "exists":
		return value != nil
	}

	return value
}

// applyDefault returns the default value with appropriate type conversion
func applyDefault(defaultValue, fieldType string) interface{} {
	if defaultValue == "" {
		return nil
	}

	switch fieldType {
	case "boolean":
		return defaultValue == "true"
	case "integer":
		return 0 // Could parse, but safer to return 0
	default:
		return defaultValue
	}
}

// SupportsLabelSelector checks if a label selector matches the resource
func SupportsLabelSelector(resourceLabels map[string]string, selector *metav1.LabelSelector) bool {
	if selector == nil {
		return true
	}

	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}

	return sel.Matches(labels.Set(resourceLabels))
}

// compileGlobToRegex converts a glob pattern to a regex for more complex matching
func compileGlobToRegex(pattern string) (*regexp.Regexp, error) {
	regexPattern := "^"
	for _, c := range pattern {
		switch c {
		case '*':
			regexPattern += ".*"
		case '?':
			regexPattern += "."
		case '.', '+', '^', '$', '[', ']', '(', ')', '{', '}', '|', '\\':
			regexPattern += "\\" + string(c)
		default:
			regexPattern += string(c)
		}
	}
	regexPattern += "$"
	return regexp.Compile(regexPattern)
}
