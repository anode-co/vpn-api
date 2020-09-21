from django.urls import path
from .views_api_0_3 import (
    AuthTestApiView,
    ServerErrorTestApiView,
)

app_name = 'common_api_0_3_authorization'

urlpatterns = [
    path('tests/auth/', AuthTestApiView.as_view(), name="test_auth"),
    path('tests/500error/', ServerErrorTestApiView.as_view(), name="test_500_error"),
]
