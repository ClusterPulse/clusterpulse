package cluster

import (
    "context"
    "time"
    "sync"
    "strings"
    
    "github.com/clusterpulse/cluster-controller/pkg/types"
    "github.com/sirupsen/logrus"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "golang.org/x/sync/errgroup"
)

// GetResourceCollection collects lightweight resource data for RBAC filtering
// Optimized for performance with limits and parallel collection
func (c *ClusterClient) GetResourceCollection(ctx context.Context, config types.CollectionConfig) (*types.ResourceCollection, error) {
    if !config.Enabled {
        return nil, nil
    }
    
    startTime := time.Now()
    collection := &types.ResourceCollection{
        Timestamp: startTime,
    }
    
    log := logrus.WithField("cluster", c.Name)
    log.Debug("Starting optimized resource collection")
    
    // Use errgroup for parallel collection with timeout
    g, gctx := errgroup.WithContext(ctx)
    
    // Mutex for safe concurrent writes
    var mu sync.Mutex
    
    // Collect pods (most important for RBAC)
    if config.MaxTotalPods > 0 {
        g.Go(func() error {
            pods, truncated := c.collectPods(gctx, config)
            mu.Lock()
            collection.Pods = pods
            if truncated {
                collection.Truncated = true
            }
            mu.Unlock()
            return nil
        })
    }
    
    // Collect deployments
    if config.MaxDeployments > 0 {
        g.Go(func() error {
            deps, _ := c.collectDeployments(gctx, config)
            mu.Lock()
            collection.Deployments = deps
            mu.Unlock()
            return nil
        })
    }
    
    // Collect services
    if config.MaxServices > 0 {
        g.Go(func() error {
            svcs, _ := c.collectServices(gctx, config)
            mu.Lock()
            collection.Services = svcs
            mu.Unlock()
            return nil
        })
    }
    
    // Collect statefulsets (only if not too many)
    if config.MaxDeployments > 0 { // Reuse deployment limit
        g.Go(func() error {
            sts, _ := c.collectStatefulSets(gctx, config)
            mu.Lock()
            collection.StatefulSets = sts
            mu.Unlock()
            return nil
        })
    }
    
    // Collect daemonsets
    g.Go(func() error {
        ds, _ := c.collectDaemonSets(gctx, config)
        mu.Lock()
        collection.DaemonSets = ds
        mu.Unlock()
        return nil
    })
    
    // Wait for all collections with timeout
    if err := g.Wait(); err != nil {
        log.WithError(err).Warn("Some resource collections failed")
        // Don't fail completely - partial data is better than none
    }
    
    // Calculate totals and timing
    collection.TotalResources = len(collection.Pods) + len(collection.Deployments) + 
                                len(collection.Services) + len(collection.StatefulSets) + 
                                len(collection.DaemonSets)
    collection.CollectionTimeMs = time.Since(startTime).Milliseconds()
    
    log.WithFields(logrus.Fields{
        "pods":           len(collection.Pods),
        "deployments":    len(collection.Deployments),
        "services":       len(collection.Services),
        "duration_ms":    collection.CollectionTimeMs,
        "truncated":      collection.Truncated,
    }).Info("Resource collection completed")
    
    return collection, nil
}

func (c *ClusterClient) collectPods(ctx context.Context, config types.CollectionConfig) ([]types.PodSummary, bool) {
    var pods []types.PodSummary
    truncated := false
    
    // Use field selector to get only running/pending pods (ignore completed)
    opts := metav1.ListOptions{
        FieldSelector: "status.phase!=Succeeded,status.phase!=Failed",
        Limit: int64(config.MaxTotalPods),
    }
    
    podList, err := c.clientset.CoreV1().Pods("").List(ctx, opts)
    if err != nil {
        logrus.WithError(err).Warn("Failed to list pods")
        return pods, false
    }
    
    // Track pods per namespace for limiting
    nsCount := make(map[string]int)
    
    for _, pod := range podList.Items {
        // Skip system namespaces if configured
        if config.NamespaceFilter != "" && strings.HasPrefix(pod.Namespace, "kube-") {
            continue
        }
        
        // Apply per-namespace limit
        if config.MaxPodsPerNS > 0 {
            if nsCount[pod.Namespace] >= config.MaxPodsPerNS {
                truncated = true
                continue
            }
            nsCount[pod.Namespace]++
        }
        
        // Apply global limit
        if len(pods) >= config.MaxTotalPods {
            truncated = true
            break
        }
        
        summary := types.PodSummary{
            Name:      pod.Name,
            Namespace: pod.Namespace,
            Status:    string(pod.Status.Phase),
            Node:      pod.Spec.NodeName,
        }
        
        // Only include labels if needed (saves memory/bandwidth)
        if config.IncludeLabels && len(pod.Labels) > 0 {
            summary.Labels = pod.Labels
        }
        
        pods = append(pods, summary)
    }
    
    return pods, truncated
}

func (c *ClusterClient) collectDeployments(ctx context.Context, config types.CollectionConfig) ([]types.DeploymentSummary, bool) {
    var deployments []types.DeploymentSummary
    
    opts := metav1.ListOptions{
        Limit: int64(config.MaxDeployments),
    }
    
    depList, err := c.clientset.AppsV1().Deployments("").List(ctx, opts)
    if err != nil {
        logrus.WithError(err).Warn("Failed to list deployments")
        return deployments, false
    }
    
    for i, dep := range depList.Items {
        if i >= config.MaxDeployments {
            break
        }
        
        // Skip system namespaces if configured
        if config.NamespaceFilter != "" && strings.HasPrefix(dep.Namespace, "kube-") {
            continue
        }
        
        summary := types.DeploymentSummary{
            Name:      dep.Name,
            Namespace: dep.Namespace,
            Replicas:  *dep.Spec.Replicas,
            Ready:     dep.Status.ReadyReplicas,
        }
        
        if config.IncludeLabels && len(dep.Labels) > 0 {
            summary.Labels = dep.Labels
        }
        
        deployments = append(deployments, summary)
    }
    
    return deployments, len(depList.Items) > config.MaxDeployments
}

func (c *ClusterClient) collectServices(ctx context.Context, config types.CollectionConfig) ([]types.ServiceSummary, bool) {
    var services []types.ServiceSummary
    
    opts := metav1.ListOptions{
        Limit: int64(config.MaxServices),
    }
    
    svcList, err := c.clientset.CoreV1().Services("").List(ctx, opts)
    if err != nil {
        logrus.WithError(err).Warn("Failed to list services")
        return services, false
    }
    
    for i, svc := range svcList.Items {
        if i >= config.MaxServices {
            break
        }
        
        // Skip system namespaces if configured
        if config.NamespaceFilter != "" && strings.HasPrefix(svc.Namespace, "kube-") {
            continue
        }
        
        summary := types.ServiceSummary{
            Name:      svc.Name,
            Namespace: svc.Namespace,
            Type:      string(svc.Spec.Type),
            ClusterIP: svc.Spec.ClusterIP,
        }
        
        if config.IncludeLabels && len(svc.Labels) > 0 {
            summary.Labels = svc.Labels
        }
        
        services = append(services, summary)
    }
    
    return services, len(svcList.Items) > config.MaxServices
}

func (c *ClusterClient) collectStatefulSets(ctx context.Context, config types.CollectionConfig) ([]types.StatefulSetSummary, bool) {
    var statefulsets []types.StatefulSetSummary
    
    opts := metav1.ListOptions{
        Limit: int64(config.MaxDeployments), // Reuse deployment limit
    }
    
    stsList, err := c.clientset.AppsV1().StatefulSets("").List(ctx, opts)
    if err != nil {
        logrus.WithError(err).Warn("Failed to list statefulsets")
        return statefulsets, false
    }
    
    for i, sts := range stsList.Items {
        if i >= config.MaxDeployments {
            break
        }
        
        if config.NamespaceFilter != "" && strings.HasPrefix(sts.Namespace, "kube-") {
            continue
        }
        
        summary := types.StatefulSetSummary{
            Name:      sts.Name,
            Namespace: sts.Namespace,
            Replicas:  *sts.Spec.Replicas,
            Ready:     sts.Status.ReadyReplicas,
        }
        
        if config.IncludeLabels && len(sts.Labels) > 0 {
            summary.Labels = sts.Labels
        }
        
        statefulsets = append(statefulsets, summary)
    }
    
    return statefulsets, len(stsList.Items) > config.MaxDeployments
}

func (c *ClusterClient) collectDaemonSets(ctx context.Context, config types.CollectionConfig) ([]types.DaemonSetSummary, bool) {
    var daemonsets []types.DaemonSetSummary
    
    // DaemonSets are usually fewer, so we can be more generous
    opts := metav1.ListOptions{
        Limit: 100,
    }
    
    dsList, err := c.clientset.AppsV1().DaemonSets("").List(ctx, opts)
    if err != nil {
        logrus.WithError(err).Warn("Failed to list daemonsets")
        return daemonsets, false
    }
    
    for _, ds := range dsList.Items {
        if config.NamespaceFilter != "" && strings.HasPrefix(ds.Namespace, "kube-") {
            continue
        }
        
        summary := types.DaemonSetSummary{
            Name:          ds.Name,
            Namespace:     ds.Namespace,
            DesiredNumber: ds.Status.DesiredNumberScheduled,
            CurrentNumber: ds.Status.CurrentNumberScheduled,
            ReadyNumber:   ds.Status.NumberReady,
        }
        
        if config.IncludeLabels && len(ds.Labels) > 0 {
            summary.Labels = ds.Labels
        }
        
        daemonsets = append(daemonsets, summary)
    }
    
    return daemonsets, false
}
