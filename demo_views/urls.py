from django.urls import include, path
from rest_framework import routers

from demo_views.django_native_views import (
    DjangoLoginRequiredView,
    DjangoNoAuthView,
    DjangoPermissionRequiredView,
    django_login_required_view,
    django_multiple_decorators_view,
    django_no_auth_view,
    django_permission_required_view,
)
from demo_views.views import (
    ActionDemoViewSet,
    AttributeDemoViewSet,
    DecoratorDemoViewSet,
    DemoAttribute,
    DemoDecorator,
    NoAuthDemo,
    example_view,
)

router = routers.DefaultRouter()

router.register(
    "decorator-viewset/",
    DecoratorDemoViewSet,
    basename="decorator-viewset",
)
router.register(
    "attribute-viewset/",
    AttributeDemoViewSet,
    basename="attribute-viewset",
)
router.register(
    "action-viewset/",
    ActionDemoViewSet,
    basename="action-viewset",
)

urlpatterns = [
    path(
        "decorator/",
        DemoDecorator.as_view(),
        name="decorator",
    ),
    path("function", example_view, name="function"),
    path(
        "attribute/",
        DemoAttribute.as_view(),
        name="attribute",
    ),
    path(
        "no-auth/",
        NoAuthDemo.as_view(),
        name="no-auth",
    ),
    # Django native authentication views
    path(
        "django-login-required/",
        django_login_required_view,
        name="django-login-required",
    ),
    path(
        "django-permission-required/",
        django_permission_required_view,
        name="django-permission-required",
    ),
    path("django-no-auth/", django_no_auth_view, name="django-no-auth"),
    path(
        "django-multiple-decorators/",
        django_multiple_decorators_view,
        name="django-multiple-decorators",
    ),
    path(
        "django-login-mixin/",
        DjangoLoginRequiredView.as_view(),
        name="django-login-mixin",
    ),
    path(
        "django-permission-mixin/",
        DjangoPermissionRequiredView.as_view(),
        name="django-permission-mixin",
    ),
    path("django-cbv-no-auth/", DjangoNoAuthView.as_view(), name="django-cbv-no-auth"),
    path("demo-viewset", include(router.urls)),
]
