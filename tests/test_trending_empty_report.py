"""Tests for the empty-history placeholder report in the trending module."""

from ravensight.trending import Trending


def test_empty_report_is_non_empty_string() -> None:
    """The empty-history report is a non-blank string."""
    result = Trending({})._empty_report()
    assert isinstance(result, str) and result.strip()
