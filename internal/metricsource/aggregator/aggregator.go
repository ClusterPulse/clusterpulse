package aggregator

import (
	"math"
	"slices"
	"time"

	"github.com/clusterpulse/cluster-controller/pkg/types"
	"github.com/sirupsen/logrus"
)

// Aggregator computes aggregations over collected resources
type Aggregator struct {
	filter *FilterEvaluator
	log    *logrus.Entry
}

// NewAggregator creates a new aggregation engine
func NewAggregator() *Aggregator {
	return &Aggregator{
		filter: NewFilterEvaluator(),
		log:    logrus.WithField("component", "aggregator"),
	}
}

// Compute calculates all aggregations for the given resources
func (a *Aggregator) Compute(input *AggregationInput) *types.AggregationResults {
	startTime := time.Now()
	results := &types.AggregationResults{
		ComputedAt: startTime,
		Values:     make(map[string]any),
	}

	a.log.Debugf("Computing %d aggregations over %d resources", len(input.Aggregations), len(input.Resources))

	for _, agg := range input.Aggregations {
		value := a.computeAggregation(&agg, input.Resources)
		results.Values[agg.Name] = value
	}

	results.DurationMs = time.Since(startTime).Milliseconds()

	if results.DurationMs > 1000 {
		a.log.Infof("Aggregation computation took %dms for %d aggregations", results.DurationMs, len(input.Aggregations))
	} else {
		a.log.Debugf("Aggregation computation completed in %dms", results.DurationMs)
	}

	return results
}

func (a *Aggregator) computeAggregation(agg *types.CompiledAggregation, resources []types.CustomCollectedResource) any {
	filtered := a.applyFilter(resources, agg.Filter)

	if agg.GroupBy != "" {
		return a.computeGrouped(agg, filtered)
	}

	return a.computeSingle(agg, filtered)
}

func (a *Aggregator) applyFilter(resources []types.CustomCollectedResource, filter *types.CompiledAggFilter) []types.CustomCollectedResource {
	if filter == nil {
		return resources
	}

	var filtered []types.CustomCollectedResource
	for i := range resources {
		if a.filter.Matches(&resources[i], filter) {
			filtered = append(filtered, resources[i])
		}
	}
	return filtered
}

func (a *Aggregator) computeSingle(agg *types.CompiledAggregation, resources []types.CustomCollectedResource) any {
	switch agg.Function {
	case types.AggFunctionCount:
		return float64(len(resources))

	case types.AggFunctionSum:
		return a.computeSum(resources, agg.Field)

	case types.AggFunctionAvg:
		return a.computeAvg(resources, agg.Field)

	case types.AggFunctionMin:
		return a.computeMin(resources, agg.Field)

	case types.AggFunctionMax:
		return a.computeMax(resources, agg.Field)

	case types.AggFunctionPercentile:
		return a.computePercentile(resources, agg.Field, agg.Percentile)

	case types.AggFunctionDistinct:
		return a.computeDistinct(resources, agg.Field)

	default:
		a.log.Warnf("Unknown aggregation function: %s", agg.Function)
		return nil
	}
}

func (a *Aggregator) computeGrouped(agg *types.CompiledAggregation, resources []types.CustomCollectedResource) map[string]any {
	groups := make(map[string][]types.CustomCollectedResource)

	for i := range resources {
		groupKey := a.getGroupKey(&resources[i], agg.GroupBy)
		groups[groupKey] = append(groups[groupKey], resources[i])
	}

	results := make(map[string]any)
	for key, groupResources := range groups {
		groupedAgg := &types.CompiledAggregation{
			Name:     agg.Name,
			Field:    agg.Field,
			Function: agg.Function,
		}
		results[key] = a.computeSingle(groupedAgg, groupResources)
	}

	return results
}

func (a *Aggregator) getGroupKey(resource *types.CustomCollectedResource, field string) string {
	val, ok := resource.Values[field]
	if !ok || val == nil {
		return "_unknown_"
	}

	switch v := val.(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return string(rune(int64(v)))
		}
		return string(rune(v))
	default:
		return "_unknown_"
	}
}

func (a *Aggregator) computeSum(resources []types.CustomCollectedResource, field string) float64 {
	var sum float64
	for i := range resources {
		val := a.getNumericValue(&resources[i], field)
		if val != nil {
			sum += *val
		}
	}
	return sum
}

func (a *Aggregator) computeAvg(resources []types.CustomCollectedResource, field string) any {
	var sum float64
	var count int
	for i := range resources {
		val := a.getNumericValue(&resources[i], field)
		if val != nil {
			sum += *val
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return sum / float64(count)
}

func (a *Aggregator) computeMin(resources []types.CustomCollectedResource, field string) any {
	var min *float64
	for i := range resources {
		val := a.getNumericValue(&resources[i], field)
		if val != nil {
			if min == nil || *val < *min {
				min = val
			}
		}
	}
	if min == nil {
		return nil
	}
	return *min
}

func (a *Aggregator) computeMax(resources []types.CustomCollectedResource, field string) any {
	var max *float64
	for i := range resources {
		val := a.getNumericValue(&resources[i], field)
		if val != nil {
			if max == nil || *val > *max {
				max = val
			}
		}
	}
	if max == nil {
		return nil
	}
	return *max
}

func (a *Aggregator) computePercentile(resources []types.CustomCollectedResource, field string, percentile int) any {
	var values []float64
	for i := range resources {
		val := a.getNumericValue(&resources[i], field)
		if val != nil {
			values = append(values, *val)
		}
	}

	if len(values) == 0 {
		return nil
	}

	slices.Sort(values)

	// Calculate percentile index
	idx := float64(percentile) / 100.0 * float64(len(values)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	frac := idx - float64(lower)

	if lower == upper {
		return values[lower]
	}
	return values[lower]*(1-frac) + values[upper]*frac
}

func (a *Aggregator) computeDistinct(resources []types.CustomCollectedResource, field string) float64 {
	unique := make(map[any]bool)
	for i := range resources {
		val, ok := resources[i].Values[field]
		if ok && val != nil {
			unique[val] = true
		}
	}
	return float64(len(unique))
}

func (a *Aggregator) getNumericValue(resource *types.CustomCollectedResource, field string) *float64 {
	val, ok := resource.Values[field]
	if !ok || val == nil {
		return nil
	}

	var result float64
	switch v := val.(type) {
	case float64:
		result = v
	case int64:
		result = float64(v)
	case int:
		result = float64(v)
	default:
		return nil
	}
	return &result
}
