# emauth/views_auth.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import (
    RegisterSerializer,
    UserProfileSerializer,
    LoginSerializer,
)
from rest_framework import permissions as drf_permissions


class RegisterView(APIView):
    permission_classes = [drf_permissions.AllowAny]

    def post(self, request):
        ser = RegisterSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = ser.save()
        return Response(UserProfileSerializer(user).data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [drf_permissions.AllowAny]

    def post(self, request):
        ser = LoginSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        result = ser.save()  
        return Response(result, status=status.HTTP_200_OK)