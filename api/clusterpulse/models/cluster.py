"""Cluster models for API responses."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ClusterHealth(str, Enum):
    """Cluster health status."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class NodeStatus(str, Enum):
    """Node status."""

    READY = "Ready"
    NOT_READY = "NotReady"
    UNKNOWN = "Unknown"
    SCHEDULING_DISABLED = "SchedulingDisabled"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class ClusterStatus(BaseModel):
    """Cluster status model."""

    health: ClusterHealth
    message: str
    last_check: datetime
    metrics_summary: Optional[Dict[str, Any]] = None


class ClusterMetrics(BaseModel):
    """Cluster metrics model."""

    timestamp: datetime
    nodes: int
    nodes_ready: int
    nodes_not_ready: int
    namespaces: int
    pods: int
    pods_running: int
    pods_pending: int
    pods_failed: int

    # Resource metrics
    cpu_capacity: float
    cpu_allocatable: float
    cpu_requested: float
    cpu_usage_percent: float

    memory_capacity: int
    memory_allocatable: int
    memory_requested: int
    memory_usage_percent: float

    storage_capacity: int
    storage_used: int

    # Additional resources
    pvcs: int = 0
    services: int = 0
    deployments: int = 0
    statefulsets: int = 0
    daemonsets: int = 0


class ClusterSpec(BaseModel):
    """Cluster specification from CRD."""

    display_name: Optional[str] = Field(None, alias="displayName")
    endpoint: str
    credentials_ref: Dict[str, str] = Field(..., alias="credentialsRef")
    labels: Dict[str, str] = Field(default_factory=dict)
    monitoring: Optional[Dict[str, Any]] = None


class Cluster(BaseModel):
    """Complete cluster model."""

    name: str
    spec: ClusterSpec
    status: ClusterStatus
    metrics: Optional[ClusterMetrics] = None

    class Config:
        allow_population_by_field_name = True


class ClusterSummary(BaseModel):
    """Cluster summary for list views."""

    name: str
    display_name: Optional[str] = None
    health: ClusterHealth
    nodes: int
    nodes_ready: int
    namespaces: int
    pods_running: int
    cpu_usage: float
    memory_usage: float
    last_check: datetime


class NodeCondition(BaseModel):
    """Node condition model."""

    type: str
    status: str
    reason: str
    message: str
    last_transition_time: str


class NodeMetrics(BaseModel):
    """Node metrics model."""

    name: str
    cluster: Optional[str] = None
    timestamp: datetime
    status: NodeStatus
    roles: List[str]
    conditions: List[NodeCondition]

    # Resource capacity
    cpu_capacity: float
    memory_capacity: int
    storage_capacity: int
    pods_capacity: int

    # Resource allocatable
    cpu_allocatable: float
    memory_allocatable: int
    storage_allocatable: int
    pods_allocatable: int

    # Resource usage
    cpu_requested: float
    memory_requested: int
    cpu_usage_percent: float
    memory_usage_percent: float

    # Pod metrics
    pods_running: int
    pods_pending: int
    pods_failed: int
    pods_succeeded: int
    pods_total: int

    # System info
    kernel_version: str
    os_image: str
    container_runtime: str
    kubelet_version: str
    architecture: str

    # Network
    internal_ip: str = ""
    external_ip: str = ""
    hostname: str = ""

    # Additional info
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    taints: List[Dict[str, str]] = Field(default_factory=list)
    images_count: int = 0
    volumes_attached: int = 0


class NodeSummary(BaseModel):
    """Node summary for list views."""

    name: str
    cluster: str
    status: NodeStatus
    roles: List[str]
    cpu_usage: float
    memory_usage: float
    pods_total: int
    pods_running: int


class NodesAggregation(BaseModel):
    """Aggregated nodes information."""

    total: int
    ready: int
    not_ready: int
    scheduling_disabled: int
    by_role: Dict[str, int]
    total_cpu_capacity: float
    total_memory_capacity: int
    avg_cpu_usage: float
    avg_memory_usage: float
    timestamp: datetime


class Operator(BaseModel):
    """Operator model."""

    name: str
    display_name: str
    version: str
    status: str
    namespace: str
    install_modes: List[str]
    provider: str
    created_at: datetime
    updated_at: datetime
    is_cluster_wide: bool
    install_mode: str
    available_in_namespaces: Optional[int] = None


class OperatorsSummary(BaseModel):
    """Operators summary."""

    total: int
    by_status: Dict[str, int]
    by_namespace: Dict[str, int]
    by_install_mode: Dict[str, int]


class Alert(BaseModel):
    """Alert model."""

    id: str
    cluster: str
    severity: AlertSeverity
    type: str
    message: str
    timestamp: datetime
    node: Optional[str] = None
    value: Optional[float] = None


class ClusterEvent(BaseModel):
    """Cluster event model."""

    type: str
    cluster: str
    timestamp: datetime
    data: Dict[str, Any]


class MetricsHistory(BaseModel):
    """Metrics history point."""

    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    cpu_requested: float
    memory_requested: int
    pods_running: int
    pods_pending: int
    pods_total: int


class AggregatedMetrics(BaseModel):
    """Aggregated metrics across all clusters."""

    clusters: Dict[str, int]
    nodes: Dict[str, int]
    workloads: Dict[str, int]
    timestamp: datetime


class HealthCheckResponse(BaseModel):
    """Health check response for Redis connection."""

    redis_connected: bool
    clusters_cached: int
    cache_age_seconds: Optional[float] = None
    message: str
