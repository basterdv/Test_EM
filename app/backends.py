from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.conf import settings
from .models import User
import jwt


class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):

        auth_header = request.headers.get('Authorization', '')
        print(auth_header)
        if not auth_header.startswith('Bearer '):
            return None

        token = auth_header.removeprefix('Bearer ').strip()
        print(settings.JWT_SECRET)
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token expired")
        except jwt.InvalidTokenError as e:
            print(e)
            raise exceptions.AuthenticationFailed("Invalid token")

        user_id = payload.get("sub")
        if not user_id:
            raise exceptions.AuthenticationFailed("Invalid token payload")

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed("User not found")

        if not user.is_active:
            raise exceptions.AuthenticationFailed("User is deactivated")

        request.user_obj = user
        request.user_permissions = set(payload.get("permissions", []))

        return user, None