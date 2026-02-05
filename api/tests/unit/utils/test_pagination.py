"""Unit tests for pagination utilities."""

import pytest

from clusterpulse.api.utils.pagination import (
    PaginatedResponse,
    PaginationParams,
    paginate,
)


class TestPaginationParams:
    """Test PaginationParams functionality."""

    def test_default_values(self):
        """Test default pagination values."""
        params = PaginationParams()
        
        assert params.page == 1
        assert params.page_size == 100
        assert params.max_page_size == 1000
        assert params.offset == 0
        assert params.effective_page_size == 100

    def test_custom_values(self):
        """Test custom pagination values."""
        params = PaginationParams(page=3, page_size=50)
        
        assert params.page == 3
        assert params.page_size == 50
        assert params.offset == 100  # (3-1) * 50
        assert params.effective_page_size == 50

    def test_offset_calculation(self):
        """Test offset calculation for different pages."""
        params = PaginationParams(page=1, page_size=20)
        assert params.offset == 0
        
        params = PaginationParams(page=2, page_size=20)
        assert params.offset == 20
        
        params = PaginationParams(page=5, page_size=20)
        assert params.offset == 80

    def test_effective_page_size_respects_max(self):
        """Test that effective_page_size respects max_page_size."""
        params = PaginationParams(page_size=2000, max_page_size=1000)
        
        assert params.page_size == 2000  # Original value preserved
        assert params.effective_page_size == 1000  # Capped at max

    def test_custom_max_page_size(self):
        """Test custom max_page_size."""
        params = PaginationParams(page_size=500, max_page_size=250)
        
        assert params.effective_page_size == 250


class TestPaginatedResponse:
    """Test PaginatedResponse functionality."""

    def test_response_structure(self):
        """Test response contains all required fields."""
        response = PaginatedResponse(
            items=["a", "b", "c"],
            total=10,
            page=1,
            page_size=3,
            total_pages=4,
            has_next=True,
            has_previous=False,
        )
        
        assert response.items == ["a", "b", "c"]
        assert response.total == 10
        assert response.page == 1
        assert response.page_size == 3
        assert response.total_pages == 4
        assert response.has_next is True
        assert response.has_previous is False

    def test_to_dict(self):
        """Test to_dict returns correct structure."""
        response = PaginatedResponse(
            items=[{"id": 1}, {"id": 2}],
            total=50,
            page=2,
            page_size=10,
            total_pages=5,
            has_next=True,
            has_previous=True,
        )
        
        result = response.to_dict()
        
        assert result["items"] == [{"id": 1}, {"id": 2}]
        assert result["pagination"]["total"] == 50
        assert result["pagination"]["page"] == 2
        assert result["pagination"]["pageSize"] == 10
        assert result["pagination"]["totalPages"] == 5
        assert result["pagination"]["hasNext"] is True
        assert result["pagination"]["hasPrevious"] is True


class TestPaginate:
    """Test paginate function."""

    @pytest.fixture
    def sample_items(self):
        """Sample items for pagination tests."""
        return list(range(1, 101))  # 1 to 100

    def test_first_page(self, sample_items):
        """Test getting first page."""
        params = PaginationParams(page=1, page_size=10)
        
        result = paginate(sample_items, params)
        
        assert result.items == list(range(1, 11))
        assert result.total == 100
        assert result.page == 1
        assert result.page_size == 10
        assert result.total_pages == 10
        assert result.has_next is True
        assert result.has_previous is False

    def test_middle_page(self, sample_items):
        """Test getting middle page."""
        params = PaginationParams(page=5, page_size=10)
        
        result = paginate(sample_items, params)
        
        assert result.items == list(range(41, 51))
        assert result.page == 5
        assert result.has_next is True
        assert result.has_previous is True

    def test_last_page(self, sample_items):
        """Test getting last page."""
        params = PaginationParams(page=10, page_size=10)
        
        result = paginate(sample_items, params)
        
        assert result.items == list(range(91, 101))
        assert result.page == 10
        assert result.has_next is False
        assert result.has_previous is True

    def test_partial_last_page(self):
        """Test last page with fewer items than page_size."""
        items = list(range(1, 26))  # 25 items
        params = PaginationParams(page=3, page_size=10)
        
        result = paginate(items, params)
        
        assert result.items == list(range(21, 26))  # Only 5 items
        assert len(result.items) == 5
        assert result.total == 25
        assert result.total_pages == 3
        assert result.has_next is False

    def test_empty_list(self):
        """Test pagination with empty list."""
        params = PaginationParams(page=1, page_size=10)
        
        result = paginate([], params)
        
        assert result.items == []
        assert result.total == 0
        assert result.total_pages == 1
        assert result.has_next is False
        assert result.has_previous is False

    def test_page_beyond_total(self, sample_items):
        """Test requesting page beyond total pages."""
        params = PaginationParams(page=20, page_size=10)  # Only 10 pages exist
        
        result = paginate(sample_items, params)
        
        assert result.items == []  # Empty because page doesn't exist
        assert result.total == 100
        assert result.total_pages == 10

    def test_single_item(self):
        """Test pagination with single item."""
        items = ["only-one"]
        params = PaginationParams(page=1, page_size=10)
        
        result = paginate(items, params)
        
        assert result.items == ["only-one"]
        assert result.total == 1
        assert result.total_pages == 1
        assert result.has_next is False
        assert result.has_previous is False

    def test_exact_page_boundary(self):
        """Test when total items equals page_size exactly."""
        items = list(range(1, 11))  # Exactly 10 items
        params = PaginationParams(page=1, page_size=10)
        
        result = paginate(items, params)
        
        assert len(result.items) == 10
        assert result.total == 10
        assert result.total_pages == 1
        assert result.has_next is False

    def test_respects_max_page_size(self, sample_items):
        """Test that pagination respects max_page_size."""
        params = PaginationParams(page=1, page_size=200, max_page_size=50)
        
        result = paginate(sample_items, params)
        
        assert len(result.items) == 50
        assert result.page_size == 50  # Uses effective_page_size

    def test_total_pages_calculation(self):
        """Test total_pages calculation for various totals."""
        # 25 items with page_size 10 = 3 pages
        result = paginate(list(range(25)), PaginationParams(page=1, page_size=10))
        assert result.total_pages == 3
        
        # 30 items with page_size 10 = 3 pages (exact)
        result = paginate(list(range(30)), PaginationParams(page=1, page_size=10))
        assert result.total_pages == 3
        
        # 31 items with page_size 10 = 4 pages
        result = paginate(list(range(31)), PaginationParams(page=1, page_size=10))
        assert result.total_pages == 4

    def test_preserves_item_types(self):
        """Test that pagination preserves item types."""
        items = [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
        params = PaginationParams(page=1, page_size=10)
        
        result = paginate(items, params)
        
        assert result.items == items
        assert result.items[0]["id"] == 1

    def test_to_dict_structure(self, sample_items):
        """Test that to_dict produces correct API response structure."""
        params = PaginationParams(page=2, page_size=25)
        
        result = paginate(sample_items, params)
        response_dict = result.to_dict()
        
        assert "items" in response_dict
        assert "pagination" in response_dict
        assert len(response_dict["items"]) == 25
        assert response_dict["pagination"]["total"] == 100
        assert response_dict["pagination"]["page"] == 2
        assert response_dict["pagination"]["pageSize"] == 25
        assert response_dict["pagination"]["totalPages"] == 4
        assert response_dict["pagination"]["hasNext"] is True
        assert response_dict["pagination"]["hasPrevious"] is True
