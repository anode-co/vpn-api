from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .serializers_0_1 import (
    VpnClientEventSerializer,
)


class CsrfExemptMixin(object):
    """Create a CSRF Excempt mixin."""

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        """Dispatch the object."""
        return super(CsrfExemptMixin, self).dispatch(*args, **kwargs)


class VpnClientEventRestApiModelViewSet(CsrfExemptMixin, ModelViewSet):
    """VPN Client Events."""

    serializer_class = VpnClientEventSerializer
    pagination_class = None

    def get_queryset(self):
        """Override the queryset."""
        return None

    def add_loggable_event(self, request):
        """Save an event that happened on a VPN API client such as crashes or routing problems."""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({})
