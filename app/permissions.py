from rest_framework import permissions
from .models import Session
from django.utils import timezone
from rest_framework import exceptions


class HasActiveSession(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            # Проверяем, авторизован ли пользователь через JWT
            if not request.user or not request.user.is_authenticated:
                # return False
                raise exceptions.AuthenticationFailed('Пользователь не найден или не авторизирован')

            session_key = request.COOKIES.get('sessionid')

            return Session.objects.filter(
                session_id=session_key,
                user=request.user,
                expire_at__gt=timezone.now()
            ).exists()
        except Exception:
            raise exceptions.AuthenticationFailed('Сессия недействительна или закрыта')


class NoActiveSession(permissions.BasePermission):
    message = "Вы уже авторизованы. Выйдите из системы, чтобы создать новый аккаунт."

    def has_permission(self, request, view):
        # Проверяем наличие сессии в куках
        session_key = request.COOKIES.get('sessionid')
        if not session_key:
            return True

        # Проверяем, активна ли эта сессия в базе
        session_exists = Session.objects.filter(
            session_id=session_key,
            expire_at__gt=timezone.now()
        ).exists()

        # Если сессия найдена, возвращаем False (403 Forbidden)
        return not session_exists


class IsAdminUserRole(permissions.BasePermission):
    """
    Разрешает доступ только пользователям с флагом is_staff или кастомной ролью.
    """

    def has_permission(self, request, view):
        # Если аутентификация прошла успешно, но пользователь не админ
        return bool(request.user and request.user.is_staff)


class RequirePermission(permissions.BasePermission):
    required_resource = None
    required_action = None

    @classmethod
    def as_perm(cls, resource, action):
        class _ConcreteRequirePermission(cls):
            required_resource = resource
            required_action = action

        return _ConcreteRequirePermission

    def has_permission(self, request, view):

        user = getattr(request, 'user_obj', None)

        if not user:
            raise exceptions.NotAuthenticated("Пользователь не авторизирован")

        required_code = f"{self.required_resource}:{self.required_action}"

        perms = getattr(request, 'user_permissions', set())

        if required_code in perms:
            return True

        raise exceptions.PermissionDenied("Доступ запрещён")
