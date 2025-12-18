from django.contrib.auth.hashers import make_password, check_password
from django.db import models


# Create your models here.
class User(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    patronymic = models.CharField(max_length=100, null=True, blank=True)

    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=255)

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_password(self, raw_password: str):
        self.password_hash = make_password(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password(raw_password, self.password_hash)

    def __str__(self):
        return self.email

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, default='')

    def __str__(self):
        return self.name


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_users')

    class Meta:
        unique_together = ('user', 'role')
class Resource(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, default='')

    def __str__(self):
        return self.name


class Action(models.Model):
    name = models.CharField(max_length=50, unique=True)  # "read", "update", ...
    description = models.TextField(blank=True, default='')

    def __str__(self):
        return self.name


class Permission(models.Model):
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE, related_name='permissions')
    action = models.ForeignKey(Action, on_delete=models.CASCADE, related_name='permissions')
    description = models.TextField(blank=True, default='')

    class Meta:
        unique_together = ('resource', 'action')

    def code(self):
        return f"{self.resource.name}:{self.action.name}"

    def __str__(self):
        return self.code()


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='permission_roles')

    class Meta:
        unique_together = ('role', 'permission')