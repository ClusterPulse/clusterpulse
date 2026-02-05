"""Aggregation computation utilities for custom resources."""

from typing import Any, Dict, List, Optional

from clusterpulse.core.logging import get_logger

logger = get_logger(__name__)


def _get_field_value(resource: Dict[str, Any], field: str) -> Optional[Any]:
    """Extract field value from resource, handling nested paths and values wrapper."""
    # First check in values dict (collector nests extracted fields there)
    values = resource.get("values", {})
    if field in values:
        return values[field]
    
    # Then check root level
    if field in resource:
        return resource[field]
    
    # Handle underscore-prefixed fields (_namespace, _name, etc.)
    if field in ("namespace", "name", "id", "labels"):
        prefixed = f"_{field}"
        if prefixed in resource:
            return resource[prefixed]
    
    # Handle dot notation for nested paths
    if "." in field:
        parts = field.split(".")
        value = resource
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value
    
    return None

def _matches_filter(
    resource: Dict[str, Any], filter_spec: Optional[Dict[str, Any]]
) -> bool:
    """Check if resource matches filter specification."""
    if not filter_spec:
        return True

    field = filter_spec.get("field")
    operator = filter_spec.get("operator", "equals")
    value = filter_spec.get("value")

    field_value = _get_field_value(resource, field)

    if operator == "equals":
        return field_value == value
    elif operator == "notEquals":
        return field_value != value
    elif operator == "greaterThan":
        return field_value is not None and field_value > value
    elif operator == "lessThan":
        return field_value is not None and field_value < value
    elif operator == "contains":
        return value in str(field_value) if field_value else False
    elif operator == "in":
        return field_value in value if isinstance(value, list) else False

    return True


def recompute_aggregations(
    resources: List[Dict[str, Any]], aggregation_specs: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Recompute aggregations from a filtered list of resources.

    Used when user has partial access and filterAggregations is enabled.
    """
    results = {}

    for spec in aggregation_specs:
        name = spec.get("name")
        function = spec.get("function")
        field = spec.get("field")
        filter_spec = spec.get("filter")
        group_by = spec.get("groupBy")

        filtered = [r for r in resources if _matches_filter(r, filter_spec)]

        try:
            if group_by:
                results[name] = _compute_grouped(filtered, function, field, group_by)
            else:
                results[name] = _compute_single(filtered, function, field, spec)
        except Exception as e:
            logger.warning(f"Failed to compute aggregation '{name}': {e}")
            results[name] = None

    return results


def _compute_single(
    resources: List[Dict[str, Any]],
    function: str,
    field: Optional[str],
    spec: Dict[str, Any],
) -> Any:
    """Compute single aggregation value."""
    if function == "count":
        return len(resources)

    if not field:
        return None

    values = [
        _get_field_value(r, field)
        for r in resources
        if _get_field_value(r, field) is not None
    ]

    if not values:
        return 0 if function in ("sum", "count") else None

    if function == "sum":
        return sum(values)
    elif function == "avg":
        return sum(values) / len(values)
    elif function == "min":
        return min(values)
    elif function == "max":
        return max(values)
    elif function == "percentile":
        p = spec.get("percentile", 95)
        sorted_vals = sorted(values)
        idx = int(len(sorted_vals) * p / 100)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]
    elif function == "distinct":
        return len(set(values))

    return None


def _compute_grouped(
    resources: List[Dict[str, Any]],
    function: str,
    field: Optional[str],
    group_by: str,
) -> Dict[str, Any]:
    """Compute grouped aggregation."""
    groups: Dict[str, List[Dict[str, Any]]] = {}

    for r in resources:
        key = str(_get_field_value(r, group_by) or "unknown")
        if key not in groups:
            groups[key] = []
        groups[key].append(r)

    return {
        k: _compute_single(v, function, field, {}) for k, v in groups.items()
    }
