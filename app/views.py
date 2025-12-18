from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import  RegisterSerializer, UserProfileSerializer, LoginSerializer,UserListSerializer,UpdateProfileSerializer
from rest_framework import permissions
from .backends import JWTAuthentication

from .models import User

class ListUser(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request, *args, **kwargs):

        users_list = User.objects.all().values()

        serializer = UserListSerializer(users_list, many=True).data

        # return Response({'users':list(users_list)}, status=status.HTTP_200_OK)
        return Response({'users': serializer}, status=status.HTTP_200_OK)

class MeView(APIView):
    authentication_classes = [JWTAuthentication]

    def get(self, request):

        user = getattr(request, 'user_obj', None)
        print(user)
        if not user:
            return Response({"detail": "Auth required"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(UserProfileSerializer(user).data)

    def patch(self, request):
        user = getattr(request, 'user_obj', None)
        if not user:
            return Response({"detail": "Auth required"}, status=status.HTTP_401_UNAUTHORIZED)

        ser = UpdateProfileSerializer(user, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(UserProfileSerializer(user).data)





class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        ser = RegisterSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = ser.save()
        return Response(UserProfileSerializer(user).data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):

        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            request.user_obj = user  # Устанавливаем атрибут user_obj в запросе
            response_data = serializer.create(serializer.validated_data)
            return Response(response_data, status=status.HTTP_200_OK)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            result = serializer.save()
        except (ObjectDoesNotExist,IntegrityError) as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(result, status=status.HTTP_200_OK)

class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            return Response({"detail": "Токен не найден."}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"detail": "Успешный выход."}, status=status.HTTP_200_OK)