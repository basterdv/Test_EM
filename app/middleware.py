from django.contrib.auth.models import AnonymousUser
from django.utils.deprecation import MiddlewareMixin
from .models import User, Session
from django.utils import timezone
from django.http import JsonResponse
from rest_framework import status

class JWTAuthMiddleware(MiddlewareMixin):
    def process_request(self, request):
        session_id = request.COOKIES.get('sessionid')
        if session_id:
            try:
                session = Session.objects.get(session_id=session_id, expire_at__gt=timezone.now())
                request.user = session.user
            except Session.DoesNotExist:
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

    def process_exception(self, request, exception):
        if isinstance(request.user, AnonymousUser):
            return JsonResponse({"detail": "Вы не авторизированны"}, status=status.HTTP_401_UNAUTHORIZED)
        return None

    # def process_exception(self, request, exception):
    #     if request.user is None:
    #         return JsonResponse({"detail": "Вы не авторизированны"}, status=status.HTTP_401_UNAUTHORIZED)
    #     return None
