from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegisterSerializer, UserProfileSerializer, LoginSerializer, UserListSerializer, \
    UpdateProfileSerializer
from rest_framework import permissions
from .backends import JWTAuthentication
# from rest_framework.permissions import IsAuthenticated
from .models import User, Session
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import uuid
from django.utils import timezone


class ListUser(APIView):
    # authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        users_list = User.objects.all().values()

        serializer = UserListSerializer(users_list, many=True).data

        # return Response({'users':list(users_list)}, status=status.HTTP_200_OK)
        return Response({'users': serializer}, status=status.HTTP_200_OK)


class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    # authentication_classes = [JWTAuthentication]

    def get(self, request):
        if request.user and request.user.is_authenticated:

            session_id = request.COOKIES.get('sessionid')
            token = request.COOKIES.get('token')
            print('session_id',session_id)
            print('token',token)

            user = getattr(request, 'user_obj', None)

            # if not user:
            #     return Response({"detail": "Вы не авторизированны"}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({'data': UserProfileSerializer(user).data, 'message': 'Вы успешно авторизованы'},
                            status=status.HTTP_200_OK)

        return Response({"detail": "Вы не авторизированны"}, status=status.HTTP_401_UNAUTHORIZED)

    def patch(self, request):
        user = getattr(request, 'user_obj', None)

        if not user:
            return Response({"detail": "Вы не авторизированны"}, status=status.HTTP_401_UNAUTHORIZED)

        ser = UpdateProfileSerializer(user, data=request.data, partial=True)
        ser.is_valid(raise_exception=True)
        ser.save()
        return Response(UserProfileSerializer(user).data)


class TestView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({'message': 'Вы успешно авторизованы'})

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'first_name', 'last_name', 'middle_name', 'password', 'password2'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email пользователя', default='root@root.ru'),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='Имя пользователя', default='Root'),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Фамилия пользователя', default='Rootov'),
                'middle_name': openapi.Schema(type=openapi.TYPE_STRING, description='Отчество пользователя', default='Rootovich'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Пароль пользователя', default='root'),
                'password2': openapi.Schema(type=openapi.TYPE_STRING, description='Повтор пароля пользователя', default='root')
            }
        ),
        responses={
            201: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Успешная регистрация')
                }
            ),
            400: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING, description='Ошибка валидации данных')
                }
            )
        }
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class RegisterView(APIView):
#     permission_classes = [permissions.AllowAny]
#
#     def post(self, request):
#         ser = RegisterSerializer(data=request.data)
#         ser.is_valid(raise_exception=True)
#         user = ser.save()
#         return Response(UserProfileSerializer(user).data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email пользователя',
                                        default='root@root.ru'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Пароль пользователя', default='root')
            }
        ),
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'token': openapi.Schema(type=openapi.TYPE_STRING, description='Ключ токена')
                }
            ),
            400: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING, description='Ошибка - ')
                }
            ),
            500: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING, description='ошибки сервера')
                }
            )
        }
    )
    def post(self, request, *args, **kwargs):
        # Проверка, авторизован ли пользователь
        if request.user and request.user.is_authenticated:
            return Response({"error": "Пользователь уже авторизован"}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            try:
                user = serializer.validated_data['user']

                session_id = uuid.uuid4().hex
                expire_at = timezone.now() + timezone.timedelta(hours=1)  # 1 hour session expiration
                Session.objects.create(user=user, session_id=session_id, expire_at=expire_at)


                # request.user_obj = user  # Устанавливаем атрибут user_obj в запросе
                response_data = serializer.create(serializer.validated_data)

                result = serializer.save()
                response = Response(result, status=status.HTTP_200_OK)
                response.set_cookie('sessionid', session_id,  httponly=True, expires=expire_at)
                # response.set_cookie('token', response_data['token'],  httponly=True, expires=expire_at)

                print(f'Session created for user {user.email} with session_id {session_id}')
                return response
            except (ObjectDoesNotExist, IntegrityError) as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    @swagger_auto_schema(
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Успешный выход')
                }
            ),
            401: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING, description='Вы не авторизированны')
                }
            )
        },
        security=[{'sessionAuth': []}]
    )
    def post(self, request):
        session_id = request.COOKIES.get('sessionid')


        if session_id:
            Session.objects.filter(session_id=session_id).delete()
            response = Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
            response.delete_cookie('sessionid')
            return response
        else:
            return Response({'message': 'Session id not exist'}, status=status.HTTP_400_BAD_REQUEST)

    # permission_classes = (permissions.IsAuthenticated,)
    #
    # def post(self, request, *args, **kwargs):
    #     session_id = request.COOKIES.get('sessionid')
    #     if session_id:
    #         Session.objects.filter(session_id=session_id).delete()
    #     response = Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)
    #     response.delete_cookie('sessionid')
    #     return response

    # serializer = self.serializer_class(data=request.data)
    #
    # if serializer.is_valid():
    #     try:
    #         serializer.create(serializer.validated_data)
    #         result = serializer.save()
    #         return Response({'data':result,"detail": "Успешный выход."}, status=status.HTTP_200_OK)
    #         # request.user.auth_token.delete()
    #     except (AttributeError, ObjectDoesNotExist):
    #         return Response({"detail": "Токен не найден."}, status=status.HTTP_400_BAD_REQUEST)
    # else:
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
