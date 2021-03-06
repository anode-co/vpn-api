"""System URL Configuration.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions
# from django.conf.urls import (
#     handler404,
# )
# from common.views_api_0_3 import error404

urlpatterns = [
    path('admin/', admin.site.urls),
]

'''
# Version  0.1
urlpatterns += [
    path('api/0.1/vpn/', include('vpn.urls_api_0_1', namespace='v0.1')),
]

# Version 0.2
urlpatterns += [
    path('api/0.2/vpn/', include('vpn.urls_api_0_2', namespace='v0.2')),
]
'''
# Version 0.3
urlpatterns += [
    path('', include('common.urls')),
    path('api/0.3/vpn/', include('vpn.urls_api_0_3_logging', namespace="Event Logging")),
    path('api/0.3/vpn/', include('vpn.urls_api_0_3_clients', namespace="Clients")),
    path('api/0.3/vpn/', include('vpn.urls_api_0_3_servers', namespace="Servers")),
    path('api/0.3/', include('common.urls_api_0_3_account_management', namespace="Account Management")),
    path('api/0.3/', include('common.urls_api_0_3_authorization', namespace="Authorization")),
    path('api/0.3/', include('common.urls_api_0_3_coordinator', namespace="Coordinator")),
]

schema_view = get_schema_view(
    openapi.Info(
        title="Anode VPN API",
        default_version="v0.3",
        description="In-development API for Anode VPN clients",
        terms_of_service="",
        contact=openapi.Contact(email="adonis@anode.co"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,)
)

urlpatterns += [
    path('swagger.<format>', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]


handler404 = 'common.views_api_0_3.error404'

admin.site.site_header = 'Anode VPN API Admin'
admin.site.site_title = 'Anode VPN API Admin Portal'
admin.site.index_title = 'Welcome to the Anode VPN API Portal'
