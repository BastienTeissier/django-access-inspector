"""
URL Analyzer Service for Django Access Inspector.

This service handles URL pattern extraction and analysis from Django URL configurations.
"""

import logging
from typing import List
from django.conf import settings
from django.core.exceptions import ViewDoesNotExist
from django.core.management.base import CommandError
from django.urls import URLPattern, URLResolver
from django.utils import translation

from .models import ViewFunction

logger = logging.getLogger(__name__)


class RegexURLPattern:
    pass


class RegexURLResolver:
    pass


class LocaleRegexURLResolver:
    pass


def describe_pattern(p):
    """Extract pattern description from URL pattern."""
    return str(p.pattern)


class UrlAnalyzerService:
    """Service responsible for extracting and analyzing URL patterns."""

    def __init__(self):
        self.LANGUAGES = getattr(settings, "LANGUAGES", [])

    def load_urlconf(self, urlconf_name: str = "ROOT_URLCONF"):
        """Load URL configuration from settings."""
        if not hasattr(settings, urlconf_name):
            msg = f"Settings module {settings} does not have the attribute {urlconf_name}."
            logger.error(msg)
            raise CommandError(msg)

        try:
            urlconf = __import__(getattr(settings, urlconf_name), {}, {}, [""])
            return urlconf
        except Exception as e:
            msg = f"Error occurred while trying to load {getattr(settings, urlconf_name)}: {str(e)}"
            logger.exception(msg)
            raise CommandError(msg)

    def extract_views_from_urlpatterns(
        self, urlpatterns, base="", namespace=None
    ) -> List[ViewFunction]:
        """
        Return a list of views from a list of urlpatterns.
        Each object in the returned list is a ViewFunction with: (view_func, regex, name)
        """
        views = []
        for p in urlpatterns:
            if isinstance(p, (URLPattern, RegexURLPattern)):
                try:
                    if not p.name:
                        name = p.name
                    elif namespace:
                        name = f"{namespace}:{p.name}"
                    else:
                        name = p.name
                    pattern = describe_pattern(p)
                    views.append(
                        ViewFunction(
                            callback=p.callback, pattern=base + pattern, name=name
                        )
                    )
                except ViewDoesNotExist:
                    logger.warning(f"View does not exist for pattern: {p}")
                    continue
            elif isinstance(p, (URLResolver, RegexURLResolver)):
                try:
                    patterns = p.url_patterns
                except ImportError as e:
                    logger.exception(f"Failed to import URL patterns for {p}: {e}")
                    continue
                if namespace and p.namespace:
                    _namespace = f"{namespace}:{p.namespace}"
                else:
                    _namespace = p.namespace or namespace
                pattern = describe_pattern(p)
                if isinstance(p, LocaleRegexURLResolver):
                    for language in self.LANGUAGES:
                        with translation.override(language[0]):
                            views.extend(
                                self.extract_views_from_urlpatterns(
                                    patterns, base + pattern, namespace=_namespace
                                )
                            )
                else:
                    views.extend(
                        self.extract_views_from_urlpatterns(
                            patterns, base + pattern, namespace=_namespace
                        )
                    )
            elif hasattr(p, "_get_callback"):
                try:
                    views.append(
                        ViewFunction(
                            callback=p._get_callback(),
                            pattern=base + describe_pattern(p),
                            name=p.name,
                        )
                    )
                except ViewDoesNotExist:
                    logger.warning(
                        f"View does not exist for pattern with _get_callback: {p}"
                    )
                    continue
            elif hasattr(p, "url_patterns") or hasattr(p, "_get_url_patterns"):
                try:
                    patterns = p.url_patterns
                except ImportError as e:
                    logger.exception(f"Failed to import URL patterns for {p}: {e}")
                    continue
                views.extend(
                    self.extract_views_from_urlpatterns(
                        patterns, base + describe_pattern(p), namespace=namespace
                    )
                )
            else:
                error_msg = f"{p} does not appear to be a urlpattern object"
                logger.error(error_msg)
                raise TypeError(error_msg)
        return views

    def analyze_urlconf(self, urlconf_name: str = "ROOT_URLCONF") -> List[ViewFunction]:
        """Analyze URL configuration and return extracted view functions."""
        urlconf = self.load_urlconf(urlconf_name)
        return self.extract_views_from_urlpatterns(urlconf.urlpatterns)
