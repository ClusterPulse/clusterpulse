package collector

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/clusterpulse/cluster-controller/internal/metricsource/aggregator"
	"github.com/clusterpulse/cluster-controller/internal/metricsource/expression"
	"github.com/clusterpulse/cluster-controller/internal/metricsource/extractor"
	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Collector handles resource collection from Kubernetes clusters
type Collector struct {
	extractor  *extractor.Extractor
	evaluator  *expression.Evaluator
	aggregator *aggregator.Aggregator
	log        *logrus.Entry
}

// NewCollector creates a new resource collector
func NewCollector() *Collector {
	return &Collector{
		extractor:  extractor.NewExtractor(),
		evaluator:  expression.NewEvaluator(),
		aggregator: aggregator.NewAggregator(),
		log:        logrus.WithField("component", "metricsource-collector"),
	}
}

// CollectResult contains the results of a collection operation
type CollectResult struct {
	Collection   *types.CustomResourceCollection
	Aggregations *types.AggregationResults
	Errors       []error
}

// Collect gathers resources from a cluster based on the MetricSource configuration
func (c *Collector) Collect(
	ctx context.Context,
	dynamicClient dynamic.Interface,
	source *types.CompiledMetricSource,
	clusterName string,
) (*CollectResult, error) {

	startTime := time.Now()
	log := logrus.WithFields(logrus.Fields{
		"cluster":      clusterName,
		"metricsource": source.Namespace + "/" + source.Name,
		"kind":         source.Source.Kind,
	})

	log.Debug("Starting resource collection")

	result := &CollectResult{
		Collection: &types.CustomResourceCollection{
			CollectedAt: startTime,
			SourceID:    source.Namespace + "/" + source.Name,
			ClusterName: clusterName,
			Resources:   make([]types.CustomCollectedResource, 0),
		},
		Errors: make([]error, 0),
	}

	// Build the GVR for the target resource
	gvr := schema.GroupVersionResource{
		Group:    source.Source.Group,
		Version:  source.Source.Version,
		Resource: source.Source.Resource,
	}

	// Determine namespaces to collect from
	namespaces, err := c.resolveNamespaces(ctx, dynamicClient, source)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve namespaces: %w", err)
	}

	log.Debugf("Collecting from %d namespaces", len(namespaces))

	// Collect resources
	var allResources []types.CustomCollectedResource
	var collectMu sync.Mutex
	var collectErrors []error
	var errorMu sync.Mutex

	// Use semaphore for parallelism control
	sem := make(chan struct{}, source.Collection.Parallelism)

	var wg sync.WaitGroup
	maxResources := int(source.Collection.MaxResources)
	truncated := false

	if source.Source.Scope == "Cluster" {
		resources, err := c.collectFromScope(ctx, dynamicClient, gvr, "", source, maxResources)
		if err != nil {
			return nil, fmt.Errorf("failed to collect cluster-scoped resources: %w", err)
		}
		allResources = resources
		truncated = len(resources) >= maxResources
	} else {
		for _, ns := range namespaces {
			collectMu.Lock()
			currentCount := len(allResources)
			collectMu.Unlock()

			if currentCount >= maxResources {
				truncated = true
				break
			}

			wg.Add(1)
			go func(namespace string) {
				defer wg.Done()

				sem <- struct{}{}
				defer func() { <-sem }()

				if ctx.Err() != nil {
					return
				}

				collectMu.Lock()
				remaining := maxResources - len(allResources)
				collectMu.Unlock()

				if remaining <= 0 {
					return
				}

				resources, err := c.collectFromScope(ctx, dynamicClient, gvr, namespace, source, remaining)
				if err != nil {
					errorMu.Lock()
					collectErrors = append(collectErrors, fmt.Errorf("namespace %s: %w", namespace, err))
					errorMu.Unlock()
					log.Debugf("Failed to collect from namespace %s: %v", namespace, err)
					return
				}

				collectMu.Lock()
				allResources = append(allResources, resources...)
				collectMu.Unlock()
			}(ns)
		}
		wg.Wait()
	}

	if len(allResources) > maxResources {
		allResources = allResources[:maxResources]
		truncated = true
	}

	result.Collection.Resources = allResources
	result.Collection.ResourceCount = len(allResources)
	result.Collection.Truncated = truncated
	result.Collection.DurationMs = time.Since(startTime).Milliseconds()
	result.Errors = collectErrors

	// Compute aggregations if defined
	if len(source.Aggregations) > 0 {
		aggInput := &aggregator.AggregationInput{
			Resources:    allResources,
			Aggregations: source.Aggregations,
		}
		result.Aggregations = c.aggregator.Compute(aggInput)
		result.Aggregations.SourceID = source.Namespace + "/" + source.Name
	}

	// Log collection results
	if len(collectErrors) > 0 {
		log.Warnf("Collection completed with %d errors: %d resources collected (truncated: %v, took %dms)",
			len(collectErrors), len(allResources), truncated, result.Collection.DurationMs)
	} else if result.Collection.DurationMs > 5000 {
		log.Infof("Collection completed: %d resources (truncated: %v, took %dms)",
			len(allResources), truncated, result.Collection.DurationMs)
	} else {
		log.Debugf("Collection completed: %d resources (truncated: %v, took %dms)",
			len(allResources), truncated, result.Collection.DurationMs)
	}

	return result, nil
}

// collectFromScope collects resources from a single namespace or cluster scope
func (c *Collector) collectFromScope(
	ctx context.Context,
	dynamicClient dynamic.Interface,
	gvr schema.GroupVersionResource,
	namespace string,
	source *types.CompiledMetricSource,
	limit int,
) ([]types.CustomCollectedResource, error) {

	var resources []types.CustomCollectedResource

	listOpts := metav1.ListOptions{
		Limit: int64(source.Collection.BatchSize),
	}

	if source.Source.LabelSelector != "" {
		listOpts.LabelSelector = source.Source.LabelSelector
	}

	var resourceInterface dynamic.ResourceInterface
	if namespace == "" {
		resourceInterface = dynamicClient.Resource(gvr)
	} else {
		resourceInterface = dynamicClient.Resource(gvr).Namespace(namespace)
	}

	for {
		if ctx.Err() != nil {
			return resources, ctx.Err()
		}

		list, err := resourceInterface.List(ctx, listOpts)
		if err != nil {
			return resources, fmt.Errorf("failed to list resources: %w", err)
		}

		for i := range list.Items {
			if len(resources) >= limit {
				return resources, nil
			}

			item := &list.Items[i]
			collected, err := c.extractResource(item, source)
			if err != nil {
				c.log.Debugf("Failed to extract resource %s/%s: %v",
					item.GetNamespace(), item.GetName(), err)
				continue
			}

			resources = append(resources, *collected)
		}

		if list.GetContinue() == "" || len(resources) >= limit {
			break
		}
		listOpts.Continue = list.GetContinue()
	}

	return resources, nil
}

// extractResource extracts configured fields and computes expressions from a single resource
func (c *Collector) extractResource(
	resource *unstructured.Unstructured,
	source *types.CompiledMetricSource,
) (*types.CustomCollectedResource, error) {

	namespace, name, labels := c.extractor.ExtractResourceIdentity(resource)

	// Extract configured fields
	values, err := c.extractor.ExtractFields(resource, source.Fields)
	if err != nil {
		return nil, fmt.Errorf("field extraction failed: %w", err)
	}

	// Evaluate computed expressions
	if len(source.Computed) > 0 {
		ctx := &expression.Context{Values: values}
		for _, comp := range source.Computed {
			if comp.Compiled != nil {
				compiledExpr, ok := comp.Compiled.(*expression.CompiledExpression)
				if !ok || compiledExpr == nil {
					continue
				}
				result, err := c.evaluator.Evaluate(compiledExpr, ctx)
				if err != nil {
					c.log.Debugf("Computed field '%s' evaluation failed: %v", comp.Name, err)
					values[comp.Name] = nil
				} else {
					values[comp.Name] = result
				}
				// Update context so subsequent computed fields can use this value
				ctx.Values[comp.Name] = values[comp.Name]
			}
		}
	}

	return &types.CustomCollectedResource{
		ID:        c.extractor.BuildResourceID(namespace, name),
		Namespace: namespace,
		Name:      name,
		Labels:    labels,
		Values:    values,
	}, nil
}

// resolveNamespaces determines which namespaces to collect from
func (c *Collector) resolveNamespaces(
	ctx context.Context,
	dynamicClient dynamic.Interface,
	source *types.CompiledMetricSource,
) ([]string, error) {

	if source.Source.Scope == "Cluster" {
		return []string{""}, nil
	}

	if source.Source.Namespaces == nil {
		return c.listAllNamespaces(ctx, dynamicClient)
	}

	allNamespaces, err := c.listAllNamespaces(ctx, dynamicClient)
	if err != nil {
		return nil, err
	}

	return c.filterNamespaces(allNamespaces, source), nil
}

// listAllNamespaces retrieves all namespace names from the cluster
func (c *Collector) listAllNamespaces(ctx context.Context, dynamicClient dynamic.Interface) ([]string, error) {
	gvr := schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}

	var namespaces []string
	listOpts := metav1.ListOptions{Limit: 500}

	for {
		list, err := dynamicClient.Resource(gvr).List(ctx, listOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to list namespaces: %w", err)
		}

		for _, item := range list.Items {
			namespaces = append(namespaces, item.GetName())
		}

		if list.GetContinue() == "" {
			break
		}
		listOpts.Continue = list.GetContinue()
	}

	return namespaces, nil
}

// filterNamespaces applies include/exclude patterns to namespace list
func (c *Collector) filterNamespaces(namespaces []string, source *types.CompiledMetricSource) []string {
	if source.NamespacePatterns == nil {
		return namespaces
	}

	var filtered []string

	for _, ns := range namespaces {
		excluded := false
		for _, pattern := range source.NamespacePatterns.Exclude {
			if pattern.MatchString(ns) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		if len(source.NamespacePatterns.Include) == 0 {
			filtered = append(filtered, ns)
			continue
		}

		for _, pattern := range source.NamespacePatterns.Include {
			if pattern.MatchString(ns) {
				filtered = append(filtered, ns)
				break
			}
		}
	}

	return filtered
}
