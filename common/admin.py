from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.translation import ugettext_lazy as _

from .models import (
    User,
    PasswordResetRequest,
    PublicKey
)
from django.contrib import admin


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    """Define admin model for custom User model with no email field."""

    fieldsets = (
        (None, {'fields': ('email', 'public_key_id', 'public_key', 'is_confirmed', 'is_app_secret_seen', 'confirmation_code', 'app_secret_token', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    list_display = ('email', 'first_name', 'last_name', 'is_staff')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)


@admin.register(PasswordResetRequest)
class PasswordResetRequestAdmin(admin.ModelAdmin):
    """Admin represtation of ClientSoftwareVersion."""

    list_display = ('password_reset_token', 'user', 'created_at', 'is_complete')
    ordering = ('is_complete', 'created_at', 'user', 'password_reset_token',)
    search_fields = ('user', 'password_reset_token')
    list_filter = ('is_complete', 'user', 'created_at')


@admin.register(PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    """Admin represtation of ClientSoftwareVersion."""

    list_display = ('public_key_id', 'public_key', 'created_at')
    ordering = ('created_at', 'public_key_id', 'public_key')
    search_fields = ('created_at', 'public_key', 'public_key_id')
    list_filter = ('created_at', )
