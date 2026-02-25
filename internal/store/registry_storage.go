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
func (c *Client) StoreRegistrySpec(ctx context.Context, name string, spec map[string]any) error {
	data, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("failed to marshal registry spec: %w", err)
	}

	key := fmt.Sprintf("registry:%s:spec", name)
	return c.client.Set(ctx, key, string(data), 0).Err() // No expiry for spec
}

// StoreRegistryStatus stores registry status
func (c *Client) StoreRegistryStatus(ctx context.Context, name string, status map[string]any) error {
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
func (c *Client) StoreRegistryMetrics(ctx context.Context, name string, metrics map[string]any) error {
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
func (c *Client) GetRegistryStatus(ctx context.Context, name string) (map[string]any, error) {
	key := fmt.Sprintf("registry:%s:status", name)
	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var status map[string]any
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
