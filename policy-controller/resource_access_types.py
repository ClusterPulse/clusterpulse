"""
Extended policy types for dynamic resource access control.

This module adds support for the new resourceAccess field in MonitorAccessPolicy
while maintaining full backward compatibility with the legacy resources section.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CompiledPatternFilter:
    """Compiled pattern filter for namespace/name matching."""
    
    include_literals: Set[str] = field(default_factory=set)
    include_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    exclude_literals: Set[str] = field(default_factory=set)
    exclude_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "include_literals": list(self.include_literals),
            "include_patterns": [(p, r.pattern) for p, r in self.include_patterns],
            "exclude_literals": list(self.exclude_literals),
            "exclude_patterns": [(p, r.pattern) for p, r in self.exclude_patterns],
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CompiledPatternFilter":
        obj = cls()
        obj.include_literals = set(data.get("include_literals", []))
        obj.exclude_literals = set(data.get("exclude_literals", []))
        for pattern, regex_str in data.get("include_patterns", []):
            obj.include_patterns.append((pattern, re.compile(regex_str)))
        for pattern, regex_str in data.get("exclude_patterns", []):
            obj.exclude_patterns.append((pattern, re.compile(regex_str)))
        return obj

    def matches(self, value: str) -> bool:
        """Check if a value matches this filter."""
        # Exclude takes precedence
        if value in self.exclude_literals:
            return False
        for _, pattern in self.exclude_patterns:
            if pattern.match(value):
                return False

        # If no include rules, allow everything not excluded
        if not self.include_literals and not self.include_patterns:
            return True

        # Check include rules
        if value in self.include_literals:
            return True
        for _, pattern in self.include_patterns:
            if pattern.match(value):
                return True

        return False


@dataclass
class CompiledLabelSelector:
    """Compiled label selector for Kubernetes-style label matching."""
    
    match_labels: Dict[str, str] = field(default_factory=dict)
    match_expressions: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "match_labels": self.match_labels,
            "match_expressions": self.match_expressions,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "CompiledLabelSelector":
        return cls(
            match_labels=data.get("match_labels", {}),
            match_expressions=data.get("match_expressions", []),
        )

    def matches(self, labels: Dict[str, str]) -> bool:
        """Check if labels match this selector."""
        if not labels:
            labels = {}

        # Check matchLabels
        for key, value in self.match_labels.items():
            if labels.get(key) != value:
                return False

        # Check matchExpressions
        for expr in self.match_expressions:
            key = expr.get("key", "")
            operator = expr.get("operator", "")
            values = set(expr.get("values", []))
            label_value = labels.get(key)

            if operator == "In":
                if label_value not in values:
                    return False
            elif operator == "NotIn":
                if label_value in values:
                    return False
            elif operator == "Exists":
                if key not in labels:
                    return False
            elif operator == "DoesNotExist":
                if key in labels:
                    return False

        return True


@dataclass
class CompiledFieldFilter:
    """Compiled filter for a specific field value."""
    
    field_name: str = ""
    include_values: Set[str] = field(default_factory=set)
    include_patterns: List[Tuple[str, re.Pattern]] = field(default_factory=list)
    exclude_values: Set[str] = field(default_factory=set)
    equals_bool: Optional[bool] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    include_if_contains: List[str] = field(default_factory=list)
    exclude_if_contains: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = {"field_name": self.field_name}
        if self.include_values:
            result["include_values"] = list(self.include_values)
        if self.include_patterns:
            result["include_patterns"] = [(p, r.pattern) for p, r in self.include_patterns]
        if self.exclude_values:
            result["exclude_values"] = list(self.exclude_values)
        if self.equals_bool is not None:
            result["equals_bool"] = self.equals_bool
        if self.min_value is not None:
            result["min_value"] = self.min_value
        if self.max_value is not None:
            result["max_value"] = self.max_value
        if self.include_if_contains:
            result["include_if_contains"] = self.include_if_contains
        if self.exclude_if_contains:
            result["exclude_if_contains"] = self.exclude_if_contains
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "CompiledFieldFilter":
        obj = cls(field_name=data.get("field_name", ""))
        obj.include_values = set(data.get("include_values", []))
        obj.exclude_values = set(data.get("exclude_values", []))
        for pattern, regex_str in data.get("include_patterns", []):
            obj.include_patterns.append((pattern, re.compile(regex_str)))
        obj.equals_bool = data.get("equals_bool")
        obj.min_value = data.get("min_value")
        obj.max_value = data.get("max_value")
        obj.include_if_contains = data.get("include_if_contains", [])
        obj.exclude_if_contains = data.get("exclude_if_contains", [])
        return obj


@dataclass
class CompiledResourceAccessFilter:
    """Complete filter for resource access control."""
    
    namespace_filter: Optional[CompiledPatternFilter] = None
    name_filter: Optional[CompiledPatternFilter] = None
    label_selector: Optional[CompiledLabelSelector] = None
    field_filters: Dict[str, CompiledFieldFilter] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.namespace_filter:
            result["namespace_filter"] = self.namespace_filter.to_dict()
        if self.name_filter:
            result["name_filter"] = self.name_filter.to_dict()
        if self.label_selector:
            result["label_selector"] = self.label_selector.to_dict()
        if self.field_filters:
            result["field_filters"] = {
                k: v.to_dict() for k, v in self.field_filters.items()
            }
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "CompiledResourceAccessFilter":
        obj = cls()
        if "namespace_filter" in data:
            obj.namespace_filter = CompiledPatternFilter.from_dict(data["namespace_filter"])
        if "name_filter" in data:
            obj.name_filter = CompiledPatternFilter.from_dict(data["name_filter"])
        if "label_selector" in data:
            obj.label_selector = CompiledLabelSelector.from_dict(data["label_selector"])
        if "field_filters" in data:
            obj.field_filters = {
                k: CompiledFieldFilter.from_dict(v)
                for k, v in data["field_filters"].items()
            }
        return obj


@dataclass
class CompiledResourceAccess:
    """Compiled resource access rule for a specific monitor."""
    
    monitor: str = ""
    visibility: str = "none"  # all, none, filtered
    filter: Optional[CompiledResourceAccessFilter] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "monitor": self.monitor,
            "visibility": self.visibility,
        }
        if self.filter:
            result["filter"] = self.filter.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict) -> "CompiledResourceAccess":
        obj = cls(
            monitor=data.get("monitor", ""),
            visibility=data.get("visibility", "none"),
        )
        if "filter" in data:
            obj.filter = CompiledResourceAccessFilter.from_dict(data["filter"])
        return obj


def compile_pattern(pattern: str) -> Tuple[str, Any]:
    """
    Compile a glob pattern to regex.
    Returns ("literal", value) for exact matches or ("regex", compiled_pattern) for patterns.
    """
    if "*" in pattern or "?" in pattern:
        regex_pattern = "^"
        for c in pattern:
            if c == "*":
                regex_pattern += ".*"
            elif c == "?":
                regex_pattern += "."
            elif c in ".+^$[](){}|\\": 
                regex_pattern += "\\" + c
            else:
                regex_pattern += c
        regex_pattern += "$"
        return ("regex", re.compile(regex_pattern))
    else:
        return ("literal", pattern)


def compile_pattern_filter(filter_spec: Dict[str, Any]) -> CompiledPatternFilter:
    """Compile a pattern filter from spec."""
    result = CompiledPatternFilter()

    for pattern in filter_spec.get("include", []):
        kind, compiled = compile_pattern(pattern)
        if kind == "literal":
            result.include_literals.add(compiled)
        else:
            result.include_patterns.append((pattern, compiled))

    for pattern in filter_spec.get("exclude", []):
        kind, compiled = compile_pattern(pattern)
        if kind == "literal":
            result.exclude_literals.add(compiled)
        else:
            result.exclude_patterns.append((pattern, compiled))

    return result


def compile_label_selector(selector_spec: Dict[str, Any]) -> CompiledLabelSelector:
    """Compile a label selector from spec."""
    return CompiledLabelSelector(
        match_labels=selector_spec.get("matchLabels", {}),
        match_expressions=selector_spec.get("matchExpressions", []),
    )


def compile_field_filter(field_name: str, filter_spec: Dict[str, Any]) -> CompiledFieldFilter:
    """Compile a field filter from spec."""
    result = CompiledFieldFilter(field_name=field_name)

    # String/enum values
    for value in filter_spec.get("include", []):
        kind, compiled = compile_pattern(str(value))
        if kind == "literal":
            result.include_values.add(compiled)
        else:
            result.include_patterns.append((str(value), compiled))

    result.exclude_values = set(str(v) for v in filter_spec.get("exclude", []))

    # Boolean
    if "equals" in filter_spec:
        result.equals_bool = bool(filter_spec["equals"])

    # Numeric
    if "min" in filter_spec:
        result.min_value = float(filter_spec["min"])
    if "max" in filter_spec:
        result.max_value = float(filter_spec["max"])

    # Array contains
    result.include_if_contains = filter_spec.get("includeIfContains", [])
    result.exclude_if_contains = filter_spec.get("excludeIfContains", [])

    return result


def compile_resource_access_filter(filter_spec: Dict[str, Any]) -> CompiledResourceAccessFilter:
    """Compile a complete resource access filter from spec."""
    result = CompiledResourceAccessFilter()

    if "namespaces" in filter_spec:
        result.namespace_filter = compile_pattern_filter(filter_spec["namespaces"])

    if "names" in filter_spec:
        result.name_filter = compile_pattern_filter(filter_spec["names"])

    if "labels" in filter_spec:
        result.label_selector = compile_label_selector(filter_spec["labels"])

    if "fields" in filter_spec:
        for field_name, field_filter_spec in filter_spec["fields"].items():
            result.field_filters[field_name] = compile_field_filter(
                field_name, field_filter_spec
            )

    return result


def compile_resource_access(access_spec: Dict[str, Any]) -> CompiledResourceAccess:
    """Compile a resource access rule from spec."""
    result = CompiledResourceAccess(
        monitor=access_spec.get("monitor", ""),
        visibility=access_spec.get("visibility", "none"),
    )

    if result.visibility == "filtered" and "filter" in access_spec:
        result.filter = compile_resource_access_filter(access_spec["filter"])

    return result


def compile_all_resource_access(rules: List[Dict[str, Any]]) -> List[CompiledResourceAccess]:
    """
    Compile all resourceAccess rules from cluster rules.
    
    Extracts resourceAccess from each cluster rule and compiles them.
    """
    compiled = []

    for rule in rules:
        for access in rule.get("resourceAccess", []):
            compiled.append(compile_resource_access(access))

    return compiled
