from django.urls import path, include

from demo_views.views import (
    DemoAttribute,
    DemoDecorator,
    example_view,
    NoAuthDemo,
    DecoratorDemoViewSet,
    AttributeDemoViewSet,
    ActionDemoViewSet,
)
from rest_framework import routers

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
    path("demo-viewset", include(router.urls)),
]
