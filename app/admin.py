from django.contrib import admin

from .models import User, Role, Permission


class UserAdmin(admin.ModelAdmin):
    list_display = (
        'email',
        'first_name',
        'last_name',
        'middle_name',
        'is_active',
        'is_staff',
    )

class UserRole(admin.ModelAdmin):
    list_display = (
        'name',
        'description',
    )

class UserPermission(admin.ModelAdmin):
    list_display = (
        'name',
        'description',
    )

admin.site.register(User, UserAdmin)
admin.site.register(Role, UserRole)
admin.site.register(Permission, UserPermission)