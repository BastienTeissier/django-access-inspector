"""
Tests for UrlAnalyzerService.

Tests cover:
- URL configuration loading
- URL pattern extraction
- Error handling and edge cases
- Namespace resolution
- Various URL pattern types
"""

from unittest.mock import Mock, patch

from django.core.exceptions import ViewDoesNotExist
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.urls import URLPattern, URLResolver

from django_access_inspector.services.models import ViewFunction
from django_access_inspector.services.url_analyzer import (
    UrlAnalyzerService,
)


class MockURLPattern(URLPattern):
    """Mock URL pattern for testing."""

    def __init__(self, pattern="test/", name="test", callback=None):
        self.pattern = Mock()
        self.pattern.__str__ = Mock(return_value=pattern)
        self.name = name
        self.callback = callback


class MockURLResolver(URLResolver):
    """Mock URL resolver for testing."""

    def __init__(self, pattern="", namespace=None, url_patterns=None):
        self.pattern = Mock()
        self.pattern.__str__ = Mock(return_value=pattern)
        self.namespace = namespace
        self.url_patterns = url_patterns or []


class MockURLConf:
    """Mock URL configuration for testing."""

    def __init__(self, urlpatterns=None):
        self.urlpatterns = urlpatterns or []


class TestUrlAnalyzerService(TestCase):
    """Test cases for UrlAnalyzerService."""

    def setUp(self):
        """Set up test dependencies."""
        self.analyzer = UrlAnalyzerService()

    def test_init(self):
        """Test UrlAnalyzerService initialization."""
        self.assertIsInstance(self.analyzer, UrlAnalyzerService)
        # Check that LANGUAGES is set from Django settings
        self.assertIsInstance(self.analyzer.LANGUAGES, list)

    @override_settings(ROOT_URLCONF="test_urlconf")
    def test_load_urlconf_success(self):
        """Test successful loading of URL configuration."""
        with patch("builtins.__import__") as mock_import:
            mock_urlconf = Mock()
            mock_import.return_value = mock_urlconf

            result = self.analyzer.load_urlconf("ROOT_URLCONF")

            self.assertEqual(result, mock_urlconf)
            mock_import.assert_called_once_with("test_urlconf", {}, {}, [""])

    def test_load_urlconf_missing_attribute(self):
        """Test loading URL configuration with missing attribute."""
        with self.assertRaises(CommandError) as cm:
            self.analyzer.load_urlconf("NON_EXISTENT_URLCONF")

        self.assertIn(
            "does not have the attribute NON_EXISTENT_URLCONF", str(cm.exception)
        )

    def test_extract_views_from_urlpatterns_empty(self):
        """Test extracting views from empty URL patterns."""
        result = self.analyzer.extract_views_from_urlpatterns([])

        self.assertEqual(result, [])

    def test_extract_views_from_urlpatterns_single_pattern(self):
        """Test extracting views from a single URL pattern."""
        mock_callback = Mock()
        pattern = MockURLPattern(
            pattern="test/", name="test_view", callback=mock_callback
        )

        result = self.analyzer.extract_views_from_urlpatterns([pattern])

        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], ViewFunction)
        self.assertEqual(result[0].callback, mock_callback)
        self.assertEqual(result[0].pattern, "test/")
        self.assertEqual(result[0].name, "test_view")

    def test_extract_views_from_urlpatterns_with_namespace(self):
        """Test extracting views with namespace."""
        mock_callback = Mock()
        pattern = MockURLPattern(
            pattern="test/", name="test_view", callback=mock_callback
        )

        result = self.analyzer.extract_views_from_urlpatterns(
            [pattern], namespace="api"
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].name, "api:test_view")

    def test_extract_views_from_urlpatterns_unnamed_pattern(self):
        """Test extracting views from unnamed patterns."""
        mock_callback = Mock()
        pattern = MockURLPattern(pattern="test/", name=None, callback=mock_callback)

        result = self.analyzer.extract_views_from_urlpatterns([pattern])

        self.assertEqual(len(result), 1)
        self.assertIsNone(result[0].name)

    def test_extract_views_from_urlpatterns_no_callback(self):
        """Test extracting views from patterns without callback."""
        pattern = MockURLPattern(pattern="test/", name="test_view", callback=None)

        result = self.analyzer.extract_views_from_urlpatterns([pattern])

        self.assertEqual(len(result), 0)

    def test_extract_views_from_urlpatterns_with_resolver(self):
        """Test extracting views from URL resolver."""
        mock_callback = Mock()
        nested_pattern = MockURLPattern(
            pattern="nested/", name="nested_view", callback=mock_callback
        )
        resolver = MockURLResolver(
            pattern="api/", namespace="api", url_patterns=[nested_pattern]
        )

        result = self.analyzer.extract_views_from_urlpatterns([resolver])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].pattern, "api/nested/")
        self.assertEqual(result[0].name, "api:nested_view")

    def test_extract_views_from_urlpatterns_view_does_not_exist(self):
        """Test handling ViewDoesNotExist exception."""
        pattern = MockURLPattern(pattern="test/", name="test_view")
        pattern.pattern.__str__ = Mock(side_effect=ViewDoesNotExist("View not found"))

        result = self.analyzer.extract_views_from_urlpatterns([pattern])

        self.assertEqual(len(result), 0)

    def test_extract_views_from_urlpatterns_resolver_import_error(self):
        """Test handling ImportError in resolver."""
        resolver = MockURLResolver(pattern="api/", namespace="api")

        # Mock the url_patterns property to raise ImportError
        type(resolver).url_patterns = Mock(side_effect=ImportError("Module not found"))

        result = self.analyzer.extract_views_from_urlpatterns([resolver])

        self.assertEqual(len(result), 0)

    def test_extract_views_from_urlpatterns_invalid_pattern(self):
        """Test handling invalid pattern objects."""
        invalid_pattern = object()

        with self.assertRaises(TypeError) as cm:
            self.analyzer.extract_views_from_urlpatterns([invalid_pattern])

        self.assertIn("does not appear to be a urlpattern object", str(cm.exception))

    @override_settings(ROOT_URLCONF="test_urlconf")
    @patch.object(UrlAnalyzerService, "load_urlconf")
    @patch.object(UrlAnalyzerService, "extract_views_from_urlpatterns")
    def test_analyze_urlconf_success(self, mock_extract, mock_load):
        """Test successful URL configuration analysis."""
        mock_urlconf = Mock()
        mock_urlconf.urlpatterns = ["pattern1", "pattern2"]
        mock_load.return_value = mock_urlconf

        expected_views = [ViewFunction(callback=Mock(), pattern="test/", name="test")]
        mock_extract.return_value = expected_views

        result = self.analyzer.analyze_urlconf()

        mock_load.assert_called_once_with("ROOT_URLCONF")
        mock_extract.assert_called_once_with(["pattern1", "pattern2"])
        self.assertEqual(result, expected_views)
