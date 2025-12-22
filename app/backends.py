from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.conf import settings
from app.models import User, Session
from django.utils import timezone
import jwt

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):

        cookie_session_id = request.COOKIES.get('sessionid')
        auth_header = request.headers.get('Authorization', '')

        if not auth_header:
            return None

        token = auth_header.removeprefix('Bearer ').strip()

        # Декодируем JWT
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Срок действия токена истек")
        except jwt.InvalidTokenError as e:
            raise exceptions.AuthenticationFailed("Недействительный токен")

        # Извлекаем данные
        user_id = payload.get("sub")
        session_id_in_token = payload.get("session_id")


        if not user_id or not session_id_in_token:
            raise exceptions.AuthenticationFailed('Payload токена неполон или Токен не привязан к сессии')

        # Проверка
        if session_id_in_token != cookie_session_id:
            raise exceptions.AuthenticationFailed('Токен не привязан к сессии')

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("Пользователь не найден")

        if not user.is_active:
            raise exceptions.AuthenticationFailed("Пользователь деактивирован")

        # Запрос в БД
        try:
            session_exists = Session.objects.filter(
                session_id=cookie_session_id,
                user=user,
                expire_at__gt=timezone.now()
            ).exists()

            if not session_exists:
                raise exceptions.AuthenticationFailed('Сессия недействительна или закрыта')

        except Exception:
            raise exceptions.AuthenticationFailed('Ошибка проверки привязки сессии')


        request.user_obj = user
        request.user_permissions = set(payload.get("permissions", []))
        return user, None
