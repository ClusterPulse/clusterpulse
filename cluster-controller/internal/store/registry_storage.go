package redis

import (
    "context"
    "encoding/json"
    "fmt"
    "time"
    
    "github.com/go-redis/redis/v8"
    "github.com/sirupsen/logrus"
)

// StoreRegistrySpec stores registry specification
func (c *Client) StoreRegistrySpec(ctx context.Context, name string, spec map[string]interface{}) error {
    data, err := json.Marshal(spec)
    if err != nil {
        return fmt.Errorf("failed to marshal registry spec: %w", err)
    }
    
    key := fmt.Sprintf("registry:%s:spec", name)
    return c.client.Set(ctx, key, string(data), 0).Err() // No expiry for spec
}

// StoreRegistryStatus stores registry status
func (c *Client) StoreRegistryStatus(ctx context.Context, name string, status map[string]interface{}) error {
    data, err := json.Marshal(status)
    if err != nil {
        return fmt.Errorf("failed to marshal registry status: %w", err)
    }
    
    pipe := c.client.Pipeline()
    
    // Store status
    statusKey := fmt.Sprintf("registry:%s:status", name)
    pipe.Set(ctx, statusKey, string(data), time.Duration(c.config.CacheTTL)*time.Second)
    
    // Update metadata
    pipe.HSet(ctx, fmt.Sprintf("registry:%s:meta", name), 
        "last_update", time.Now().UTC().Format(time.RFC3339),
        "available", fmt.Sprintf("%v", status["available"]),
    )
    
    // Add to registry set
    pipe.SAdd(ctx, "registries:all", name)
    
    _, err = pipe.Exec(ctx)
    return err
}

// StoreRegistryMetrics stores registry metrics time series
func (c *Client) StoreRegistryMetrics(ctx context.Context, name string, metrics map[string]interface{}) error {
    metricsJSON, err := json.Marshal(metrics)
    if err != nil {
        return fmt.Errorf("failed to marshal registry metrics: %w", err)
    }
    
    pipe := c.client.Pipeline()
    
    // Store in sorted set for time series
    metricsKey := fmt.Sprintf("registry:%s:metrics", name)
    timestamp := time.Now().Unix()
    if ts, ok := metrics["timestamp"].(int64); ok {
        timestamp = ts
    }
    
    pipe.ZAdd(ctx, metricsKey, &redis.Z{
        Score:  float64(timestamp),
        Member: string(metricsJSON),
    })
    
    // Trim old metrics (keep last hour by default)
    cutoff := time.Now().Add(-time.Duration(c.config.MetricsRetention) * time.Second).Unix()
    pipe.ZRemRangeByScore(ctx, metricsKey, "-inf", fmt.Sprintf("%d", cutoff))
    
    // Set TTL
    pipe.Expire(ctx, metricsKey, time.Duration(c.config.MetricsRetention)*time.Second)
    
    // Store latest metrics for quick access
    latestKey := fmt.Sprintf("registry:%s:metrics:latest", name)
    pipe.Set(ctx, latestKey, string(metricsJSON), time.Duration(c.config.CacheTTL)*time.Second)
    
    _, err = pipe.Exec(ctx)
    return err
}

// GetRegistryStatus retrieves registry status
func (c *Client) GetRegistryStatus(ctx context.Context, name string) (map[string]interface{}, error) {
    key := fmt.Sprintf("registry:%s:status", name)
    data, err := c.client.Get(ctx, key).Result()
    if err != nil {
        return nil, err
    }
    
    var status map[string]interface{}
    if err := json.Unmarshal([]byte(data), &status); err != nil {
        return nil, err
    }
    
    return status, nil
}

// GetAllRegistries retrieves all registry names
func (c *Client) GetAllRegistries(ctx context.Context) ([]string, error) {
    members, err := c.client.SMembers(ctx, "registries:all").Result()
    if err != nil {
        return nil, err
    }
    return members, nil
}

// GetRegistryMetricsRange retrieves registry metrics for a time range
func (c *Client) GetRegistryMetricsRange(ctx context.Context, name string, start, end time.Time) ([]map[string]interface{}, error) {
    key := fmt.Sprintf("registry:%s:metrics", name)
    
    results, err := c.client.ZRangeByScore(ctx, key, &redis.ZRangeBy{
        Min: fmt.Sprintf("%d", start.Unix()),
        Max: fmt.Sprintf("%d", end.Unix()),
    }).Result()
    
    if err != nil {
        return nil, err
    }
    
    metrics := make([]map[string]interface{}, 0, len(results))
    for _, result := range results {
        var m map[string]interface{}
        if err := json.Unmarshal([]byte(result), &m); err != nil {
            logrus.WithError(err).Debug("Failed to unmarshal metric entry")
            continue
        }
        metrics = append(metrics, m)
    }
    
    return metrics, nil
}

// DeleteRegistryData deletes all data for a registry
func (c *Client) DeleteRegistryData(ctx context.Context, name string) error {
    pattern := fmt.Sprintf("registry:%s:*", name)
    
    // Use SCAN to find all keys
    iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
    
    pipe := c.client.Pipeline()
    count := 0
    
    for iter.Next(ctx) {
        pipe.Del(ctx, iter.Val())
        count++
        
        // Execute in batches
        if count%100 == 0 {
            if _, err := pipe.Exec(ctx); err != nil {
                return err
            }
            pipe = c.client.Pipeline()
        }
    }
    
    if count%100 != 0 {
        if _, err := pipe.Exec(ctx); err != nil {
            return err
        }
    }
    
    // Remove from registries set
    c.client.SRem(ctx, "registries:all", name)
    
    logrus.Debugf("Deleted %d keys for registry %s", count, name)
    
    return iter.Err()
}

// GetRegistrySummary returns a summary of all registries
func (c *Client) GetRegistrySummary(ctx context.Context) (map[string]interface{}, error) {
    registries, err := c.GetAllRegistries(ctx)
    if err != nil {
        return nil, err
    }
    
    summary := map[string]interface{}{
        "total":      len(registries),
        "available":  0,
        "unavailable": 0,
        "registries": []map[string]interface{}{},
    }
    
    registryList := []map[string]interface{}{}
    
    for _, name := range registries {
        status, err := c.GetRegistryStatus(ctx, name)
        if err != nil {
            logrus.WithError(err).Debugf("Failed to get status for registry %s", name)
            continue
        }
        
        // Get spec for display name
        specKey := fmt.Sprintf("registry:%s:spec", name)
        specData, _ := c.client.Get(ctx, specKey).Result()
        
        var spec map[string]interface{}
        if specData != "" {
            json.Unmarshal([]byte(specData), &spec)
        }
        
        regInfo := map[string]interface{}{
            "name":          name,
            "display_name":  spec["display_name"],
            "endpoint":      spec["endpoint"],
            "type":          spec["type"],
            "available":     status["available"],
            "response_time": status["response_time"],
            "last_check":    status["last_check"],
        }
        
        if available, ok := status["available"].(bool); ok && available {
            summary["available"] = summary["available"].(int) + 1
        } else {
            summary["unavailable"] = summary["unavailable"].(int) + 1
        }
        
        registryList = append(registryList, regInfo)
    }
    
    summary["registries"] = registryList
    
    return summary, nil
}
