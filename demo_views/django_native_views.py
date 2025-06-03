"""
Test views to demonstrate Django-native authentication detection.
"""

from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.http import HttpResponse
from django.views.decorators.cache import cache_page
from django.views.generic import TemplateView


# Plain Django function-based view with login_required decorator
@login_required
def django_login_required_view(request):
    """A view that requires login via Django's @login_required decorator."""
    return HttpResponse("This view requires login")


# Plain Django function-based view with permission_required decorator
@permission_required("auth.add_user")
def django_permission_required_view(request):
    """A view that requires specific permission via Django's @permission_required decorator."""
    return HttpResponse("This view requires add_user permission")


# Plain Django function-based view with no authentication
def django_no_auth_view(request):
    """A view with no authentication requirements."""
    return HttpResponse("This view has no authentication")


# Django class-based view with LoginRequiredMixin
class DjangoLoginRequiredView(LoginRequiredMixin, TemplateView):
    """A class-based view that requires login via LoginRequiredMixin."""

    template_name = "test.html"


# Django class-based view with PermissionRequiredMixin
class DjangoPermissionRequiredView(PermissionRequiredMixin, TemplateView):
    """A class-based view that requires permission via PermissionRequiredMixin."""

    template_name = "test.html"
    permission_required = "auth.add_user"


# Django class-based view with no authentication
class DjangoNoAuthView(TemplateView):
    """A class-based view with no authentication requirements."""

    template_name = "test.html"


# Multiple decorators
@cache_page(60)
@login_required
def django_multiple_decorators_view(request):
    """A view with multiple decorators including login_required."""
    return HttpResponse("This view has multiple decorators")
