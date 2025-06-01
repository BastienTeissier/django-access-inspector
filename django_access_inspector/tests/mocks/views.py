from typing import Any, Optional

from django.http import HttpRequest
from rest_framework import mixins, status, viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import (
    action,
    api_view,
    authentication_classes,
    permission_classes,
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django_access_inspector.tests.mocks.permissions import TestOnly


@permission_classes([IsAuthenticated, TestOnly])
@authentication_classes([SessionAuthentication])
class DemoDecorator(APIView):
    def get(self, request: HttpRequest, format: Optional[str] = None) -> Response:
        return Response("toto", status=status.HTTP_201_CREATED)

    def post(self, request: HttpRequest, format: Optional[str] = None) -> Response:
        return Response("toto", status=status.HTTP_400_BAD_REQUEST)


class DemoAttribute(APIView):
    permission_classes = [IsAuthenticated, TestOnly]
    authentication_classes = [SessionAuthentication]

    def get(self, request: HttpRequest, format: Optional[str] = None) -> Response:
        return Response("toto", status=status.HTTP_201_CREATED)

    def post(self, request: HttpRequest, format: Optional[str] = None) -> Response:
        return Response("toto", status=status.HTTP_400_BAD_REQUEST)


class NoAuthDemo(APIView):
    def get(self, request: HttpRequest, format: Optional[str] = None) -> Response:
        return Response("toto", status=status.HTTP_201_CREATED)

    def post(self, request: HttpRequest, format: Optional[str] = None) -> Response:
        return Response("toto", status=status.HTTP_400_BAD_REQUEST)


@permission_classes([IsAuthenticated, TestOnly])
@authentication_classes([SessionAuthentication])
class DecoratorDemoViewSet(
    viewsets.GenericViewSet,
    mixins.RetrieveModelMixin,
):
    def retrieve(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        return super().retrieve(request, *args, **kwargs)


class AttributeDemoViewSet(
    viewsets.GenericViewSet,
    mixins.RetrieveModelMixin,
):
    permission_classes = [IsAuthenticated, TestOnly]
    authentication_classes = [SessionAuthentication]

    def retrieve(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        return super().retrieve(request, *args, **kwargs)


@authentication_classes([SessionAuthentication])
class ActionDemoViewSet(
    viewsets.GenericViewSet,
):
    @action(
        methods=["get"],
        detail=True,
        permission_classes=[TestOnly],
        authentication_classes=[SessionAuthentication],
    )
    def preview(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        content = {"status": "request was permitted"}
        return Response(content)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
@authentication_classes([SessionAuthentication])
def example_view(request: HttpRequest, format: Optional[str] = None) -> Response:
    content = {"status": "request was permitted"}
    return Response(content)
