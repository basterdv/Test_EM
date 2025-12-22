from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import exceptions
from .permissions import HasActiveSession, NoActiveSession, RequirePermission
from .serializers import RegisterSerializer, UserProfileSerializer, LoginSerializer, UserListSerializer, \
    PermissionAddSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from app.backends import JWTAuthentication

from .models import User, Session, Role, RolePermission, Permission, UserRole
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import uuid
from django.utils import timezone

from faker import Faker


class ListUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [HasActiveSession, RequirePermission.as_perm("reports", "read")]

    def get(self, request, *args, **kwargs):
        users_list = User.objects.all()

        serializer = UserListSerializer(users_list, many=True).data

        # return Response({'users':list(users_list)}, status=status.HTTP_200_OK)
        return Response({'users': serializer}, status=status.HTTP_200_OK)


class MeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [HasActiveSession]

    @swagger_auto_schema(
        responses={
            200: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING, description='Данные профиля пользователя')
                }
            ),
            400: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING, description='Ошибка в запросе')
                }
            ),
            500: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING, description='ошибки сервера')
                }
            ),
            403: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING, description='Доступ ограничен'),
                    'details': openapi.Schema(type=openapi.TYPE_STRING,
                                              description='Подробная информация о причине отказа в доступе')
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
    def get(self, request):
        try:
            user = getattr(request, 'user_obj', None)

            if not user:
                return Response(
                    {
                        "detail": "Вы не авторизированны на этом устройстве, нужно повторить авторизацию"
                    },
                    status=status.HTTP_401_UNAUTHORIZED
                )

            return Response(
                {
                    'data': UserProfileSerializer(user).data, 'message': 'Вы успешно авторизованы'
                },
                status=status.HTTP_200_OK
            )

        except exceptions.AuthenticationFailed as e:
            return Response(
                {
                    "error": str(e)
                },
                status=status.HTTP_403_FORBIDDEN
            )
        except (
                ObjectDoesNotExist,
                IntegrityError
        ) as e:
            return Response(
                {
                    "error": str(e)
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class DeleteMeView(APIView):
    authentication_classes = [JWTAuthentication]

    def delete(self, request):
        user = getattr(request, 'user_obj', None)
        if not user:
            return Response({"detail": "Доступ запрещен"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user.is_active = False
            user.save()
            response = Response(
                {'message': f'Пользователь {user} удалён успешно'},
                status=status.HTTP_204_NO_CONTENT
            )
            response.delete_cookie('sessionid')
            return response
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(APIView):
    permission_classes = [AllowAny, NoActiveSession]

    fake = Faker()

    user_data = {
        'email': fake.email(),
        'first_name': fake.last_name(),
        'last_name': fake.last_name(),
        'middle_name': fake.first_name(),
        'password': fake.password(length=10),
    }
    password = user_data.get('password')

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'first_name', 'last_name', 'middle_name', 'password', 'password2'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email пользователя',
                                        default=user_data.get('email')),
                'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='Имя пользователя',
                                             default=user_data.get('first_name')),
                'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Фамилия пользователя',
                                            default=user_data.get('last_name')),
                'middle_name': openapi.Schema(type=openapi.TYPE_STRING, description='Отчество пользователя',
                                              default=user_data.get('middle_name')),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Пароль пользователя',
                                           default=password),
                'password_repeat': openapi.Schema(type=openapi.TYPE_STRING, description='Повтор пароля пользователя',
                                                  default=password)
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
            return Response({'message': f'Пользователь {user} зарегистрирован успешно'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

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
    def post(self, request):
        session_id = uuid.uuid4().hex
        data_with_session_id = request.data.copy()
        data_with_session_id['session_id'] = session_id

        serializer = LoginSerializer(data=data_with_session_id)

        if serializer.is_valid():
            try:

                user = serializer.validated_data['user']
                request.user_obj = user  # Устанавливаем атрибут user_obj в запросе

                token = serializer.create(serializer.validated_data)['token']

                expire_at = timezone.now() + timezone.timedelta(hours=1)  # 1 hour session expiration
                Session.objects.create(user=user, session_id=session_id, token_id=token, expire_at=expire_at)

            except PermissionDenied as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_403_FORBIDDEN
                )
            except (ObjectDoesNotExist, IntegrityError) as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        result = serializer.save()
        response = Response(result, status=status.HTTP_200_OK)
        response.set_cookie(
            'sessionid', session_id,
            httponly=True,
            expires=expire_at,
            secure=True,
        )
        return response


class LogoutView(APIView):
    # permission_classes = [HasActiveCustomSession]

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
            response = Response({'message': 'Успешный выход'}, status=status.HTTP_200_OK)
            response.delete_cookie('sessionid')
            return response
        else:
            return Response({'message': 'Ошибка сессии'}, status=status.HTTP_400_BAD_REQUEST)


class AdminRolesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("adminpanel", "manage")]

    def get(self, request):
        data = []
        for role in Role.objects.all():

            perms = []

            rps = role.role_permissions.select_related(
                'permission__resource',
                'permission__action'
            )

            for rp in rps:
                perms.append(rp.permission.code())

            data.append({
                "role_id": role.id,
                "role_name": role.name,
                "permissions": perms,
            })

        return Response({"roles": data})


class AdminGrantRoleView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("adminpanel", "manage")]

    def post(self, request, role_id):
        user_id = request.data.get("user_id")
        user = get_object_or_404(User, id=user_id)
        role = get_object_or_404(Role, id=role_id)

        UserRole.objects.get_or_create(user=user, role=role)
        return Response({"status": "ok"}, status=status.HTTP_200_OK)


class AdminAddPermissionToRoleView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("adminpanel", "manage")]

    # serializer_class = PermissionAddSerializer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['permission'],
            properties={
                'permission': openapi.Schema(type=openapi.TYPE_STRING, description='Email пользователя',
                                        default='reports:update'),
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
    def post(self, request, role_id):
        try:

            perm_code = request.data.get("permission")  # пример: "reports:update"
            print(perm_code)

            res_name, action_name = perm_code.split(":", 1)

            perm = Permission.objects.select_related('resource', 'action').get(
                resource__name=res_name,
                action__name=action_name
            )
            role = get_object_or_404(Role, id=role_id)

            RolePermission.objects.get_or_create(role=role, permission=perm)
            return Response({"status": "ok"}, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, IntegrityError) as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
