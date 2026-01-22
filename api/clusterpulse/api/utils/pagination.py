"""Pagination utilities for API endpoints."""

from dataclasses import dataclass
from math import ceil
from typing import Any, Dict, List


@dataclass
class PaginationParams:
    """Pagination parameters from query string."""

    page: int = 1
    page_size: int = 100
    max_page_size: int = 1000

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.effective_page_size

    @property
    def effective_page_size(self) -> int:
        return min(self.page_size, self.max_page_size)


@dataclass
class PaginatedResponse:
    """Paginated response container."""

    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_previous: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "items": self.items,
            "pagination": {
                "total": self.total,
                "page": self.page,
                "pageSize": self.page_size,
                "totalPages": self.total_pages,
                "hasNext": self.has_next,
                "hasPrevious": self.has_previous,
            },
        }


def paginate(items: List[Any], params: PaginationParams) -> PaginatedResponse:
    """Apply pagination to a list of items."""
    total = len(items)
    page_size = params.effective_page_size
    total_pages = ceil(total / page_size) if total > 0 else 1

    start = params.offset
    end = start + page_size
    page_items = items[start:end]

    return PaginatedResponse(
        items=page_items,
        total=total,
        page=params.page,
        page_size=page_size,
        total_pages=total_pages,
        has_next=params.page < total_pages,
        has_previous=params.page > 1,
    )
