import uuid

from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from django.utils import timezone
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from faker import Faker
from rest_framework import exceptions
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from app.backends import JWTAuthentication
from .models import User, Session, Role, RolePermission, Permission, UserRole
from .permissions import HasActiveSession, NoActiveSession, RequirePermission
from .serializers import RegisterSerializer, UserProfileSerializer, LoginSerializer, UserListSerializer, \
    PermissionAddSerializer, GrantRoleSerializer

fake = Faker(['ru_RU'])

# Генерируем 10 фейковых отчетов
FAKE_REPORTS = [
    {
        "id": i,
        "title": fake.catch_phrase(),
        "owner": fake.name(),
        "created_at": fake.date_this_year().isoformat(),
        "content": fake.text(max_nb_chars=100)
    } for i in range(1, 11)
]


class ListUser(APIView):
    """
        Список пользователей
        Доступ: право 'reports:read' (403).
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [HasActiveSession, RequirePermission.as_perm("reports", "read")]

    @swagger_auto_schema(
        operation_summary="Получить список пользователей",
        operation_description="Доступ только для пользователей с правом 'reports:read'.",
        responses={
            200: openapi.Response(
                description="Список пользователей успешно получен",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'users': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(type=openapi.TYPE_OBJECT),
                            description="Массив объектов пользователей"
                        )
                    }
                )
            ),
            403: "Ошибка доступа (недостаточно прав)",
            401: "Ошибка авторизации (токен невалиден)"
        },
        tags=['Пользователи']
    )
    def get(self, request, *args, **kwargs):
        users_list = User.objects.all()

        serializer = UserListSerializer(users_list, many=True).data
        return Response({'users': serializer}, status=status.HTTP_200_OK)


class ReportsListView(APIView):
    """
        Получение списка отчетов.
        Доступ: Требуется валидный JWT + Сессия в БД (401)
        и право 'reports:read' (403).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("reports", "read")]

    @swagger_auto_schema(
        operation_summary="Получение списка отчетов",
        operation_description="Метод возвращает все доступные отчеты. Требуется право доступа 'reports:read'.",
        responses={
            200: openapi.Response(
                description="Успешный ответ со списком отчетов",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'count': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description="Общее количество отчетов"
                        ),
                        'reports': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'id': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID отчета"),
                                    'title': openapi.Schema(type=openapi.TYPE_STRING, description="Заголовок отчета"),
                                    'status': openapi.Schema(type=openapi.TYPE_STRING, description="Текущий статус")
                                }
                            ),
                            description="Массив объектов отчетов"
                        ),
                    }
                ),
                example={
                    "count": 2,
                    "reports": FAKE_REPORTS
                }
            ),
            401: "Ошибка авторизации (недействительный JWT или сессия)",
            403: "Недостаточно прав (отсутствует reports:read)"
        },
        tags=['Отчетность']
    )
    def get(self, request):
        return Response({
            "count": len(FAKE_REPORTS),
            "reports": FAKE_REPORTS
        })


class ReportsUpdateView(APIView):
    """
        Обновление отчета.
        Доступ: право 'reports:update' (403).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("reports", "update")]

    @swagger_auto_schema(
        operation_summary="Обновление данных отчета",
        operation_description="Обновляет состояние отчета по его ID. Требуется право: reports:update.",
        manual_parameters=[
            openapi.Parameter(
                'report_id',
                openapi.IN_PATH,
                description="Уникальный идентификатор отчета",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description="Отчет успешно обновлен",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, example="success"),
                        'updated_report': openapi.Schema(type=openapi.TYPE_STRING,
                                                         description="Название обновленного отчета"),
                        'modified_at': openapi.Schema(type=openapi.TYPE_STRING, format="date-time",
                                                      description="Время изменения")
                    }
                )
            ),
            404: openapi.Response(
                description="Ошибка: Отчет не найден",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={'error': openapi.Schema(type=openapi.TYPE_STRING, example="Отчет не найден")}
                )
            ),
            403: "Ошибка доступа: недостаточно прав",
            401: "Ошибка авторизации: невалидный токен"
        },
        tags=['Отчетность']
    )
    def post(self, request, report_id: int):
        # Поиск отчета в  фейковом списке
        report = next((r for r in FAKE_REPORTS if r["id"] == report_id), None)

        if not report:
            return Response({"error": "Отчет не найден"}, status=404)

        return Response({
            "status": "success",
            "updated_report": report["title"],
            "modified_at": timezone.now().isoformat()
        })


class MeView(APIView):
    """
        Проверка корректной аутентификации и авторизации
        Доступ: Требуется валидный JWT + Сессия в БД (401)
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [HasActiveSession]

    @swagger_auto_schema(
        operation_summary="Профиль текущего пользователя",
        operation_description="Метод позволяет проверить статус авторизации и получить данные профиля текущего пользователя.",
        responses={
            200: openapi.Response(
                description="Успешная авторизация",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            # Ссылка на поля сериализатора для автоматического описания
                            description="Данные профиля пользователя (см. UserProfileSerializer)"
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example="Вы успешно авторизованы"
                        )
                    }
                )
            ),
            401: openapi.Response(
                description="Сессия не найдена или истекла",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example="Вы не авторизированны на этом устройстве..."
                        )
                    }
                )
            ),
            400: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING,
                                            description="Ошибка базы данных или отсутствие объекта")
                }
            ),
            403: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING,
                                            description="Ошибка доступа или невалидные учетные данные")
                }
            ),
            500: openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'error': openapi.Schema(type=openapi.TYPE_STRING, description="Внутренняя ошибка сервера")
                }
            )
        },
        tags=['Профиль']
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
    """
        Мягкое удаление пользователя который в данный момент аутентифицирован и авторизирован
        Доступ: Требуется валидный JWT + Сессия в БД (401)
    """
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="Удаление текущего профиля",
        operation_description=(
                "Выполняет мягкое удаление (деактивацию) учетной записи текущего пользователя. "
                "После выполнения устанавливается флаг is_active = False, а сессия удаляется из куки."
        ),
        responses={
            204: openapi.Response(
                description="Пользователь успешно деактивирован. Контент не возвращается.",
                # Несмотря на 204, для документации можно описать ожидаемое сообщение
                examples={"application/json": {"message": "Пользователь admin удалён успешно"}}
            ),
            401: openapi.Response(
                description="Неавторизованный доступ",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={'detail': openapi.Schema(type=openapi.TYPE_STRING, example="Доступ запрещен")}
                )
            ),
            400: openapi.Response(
                description="Ошибка при выполнении операции",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={'detail': openapi.Schema(type=openapi.TYPE_STRING)}
                )
            )
        },
        tags=['Профиль']
    )
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
    """
        Регистрация нового пользователя
        Доступ для всех
    """
    permission_classes = [AllowAny, NoActiveSession]

    # Файковые данные для теста
    user_data = {
        'email': fake.email(),
        'first_name': fake.last_name(),
        'last_name': fake.last_name(),
        'middle_name': fake.first_name(),
        'password': fake.password(length=10),
    }
    password = user_data.get('password')

    @swagger_auto_schema(
        operation_summary="Регистрация нового пользователя",
        operation_description=(
                "Создает новую учетную запись в системе. "
                "Пароль должен соответствовать требованиям безопасности (минимум 8 символов)."
        ),
        # Указываем сериализатор для генерации полей ввода в Swagger
        request_body=RegisterSerializer,
        responses={
            201: openapi.Response(
                description="Пользователь успешно зарегистрирован",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example="Пользователь ivan@example.com зарегистрирован успешно"
                        )
                    }
                )
            ),
            400: openapi.Response(
                description="Ошибка валидации данных",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'email': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING),
                                                example=["Пользователь с таким email уже существует."]),
                        'password': openapi.Schema(type=openapi.TYPE_ARRAY,
                                                   items=openapi.Items(type=openapi.TYPE_STRING),
                                                   example=["Пароль слишком короткий."])
                    }
                )
            )
        },
        tags=['Авторизация и Регистрация']
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': f'Пользователь {user} зарегистрирован успешно'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
        Аутентификация пользователя
        Доступ: для всех
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Авторизация пользователя",
        operation_description=(
                "Принимает email и password. Возвращает JWT-токен и устанавливает "
                "HTTP-only куку 'sessionid'. Сессия действительна в течение 1 часа."
        ),
        request_body=LoginSerializer,
        responses={
            200: openapi.Response(
                description="Успешный вход",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'token': openapi.Schema(type=openapi.TYPE_STRING, description="JWT access token"),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT, description="Данные пользователя")
                    }
                ),
                headers={
                    'Set-Cookie': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="sessionid=...; HttpOnly; Secure; Expires=..."
                    )
                }
            ),
            400: "Ошибка валидации (неверный формат данных)",
            403: "Доступ запрещен (неверные учетные данные или заблокирован)",
            500: "Внутренняя ошибка сервера (ошибка БД)"
        },
        tags=['Авторизация и Регистрация']
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
    """
        Выход из текущей сессии
    """

    @swagger_auto_schema(
        operation_summary="Выход из системы",
        operation_description=(
                "Удаляет запись о сессии из базы данных и очищает куку 'sessionid' в браузере. "
                "Если кука отсутствует, возвращается ошибка 400."
        ),
        responses={
            200: openapi.Response(
                description="Успешное завершение сессии",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, example="Успешный выход")
                    }
                ),
                headers={
                    'Set-Cookie': openapi.Schema(
                        type=openapi.TYPE_STRING,
                        description="Удаление куки: sessionid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
                    )
                }
            ),
            400: openapi.Response(
                description="Невалидная сессия или отсутствие куки",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING, example="Ошибка сессии")
                    }
                )
            )
        },
        tags=['Авторизация и Регистрация']
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
    """
        Получение списка ролей для администраторов.
        Доступ: Требуется валидный JWT + Сессия в БД (401)
        и право 'adminpanel:manage' (403).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("adminpanel", "manage")]

    @swagger_auto_schema(
        operation_summary="Список ролей и прав доступа",
        operation_description=(
                "Возвращает все существующие в системе роли с полным списком связанных прав. "
                "Доступно только для пользователей с правом 'adminpanel:manage'."
        ),
        responses={
            200: openapi.Response(
                description="Успешное получение списка ролей",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'roles': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Items(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'role_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="ID роли"),
                                    'role_name': openapi.Schema(type=openapi.TYPE_STRING,
                                                                description="Наименование роли"),
                                    'permissions': openapi.Schema(
                                        type=openapi.TYPE_ARRAY,
                                        items=openapi.Items(type=openapi.TYPE_STRING),
                                        description="Список кодов разрешений (например, 'reports:read')"
                                    ),
                                }
                            )
                        )
                    }
                ),
                example={
                    "roles": [
                        {
                            "role_id": 1,
                            "role_name": "Администратор ВАК",
                            "permissions": ["reports:read", "adminpanel:manage", "users:write"]
                        }
                    ]
                }
            ),
            401: "Ошибка аутентификации (JWT/Сессия невалидны)",
            403: "Ошибка доступа (отсутствует право adminpanel:manage)"
        },
        tags=['Администрирование']
    )
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
    """
        Назначить роль пользователю.
        Доступ: Требуется валидный JWT + Сессия в БД (401)
        и право 'adminpanel:manage' (403).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("adminpanel", "manage")]

    @swagger_auto_schema(
        operation_summary="Назначение роли пользователю",
        operation_description=(
                "Метод связывает указанного пользователя с указанной ролью. "
                "Если связь уже существует, возвращается ошибка."
        ),
        manual_parameters=[
            openapi.Parameter(
                'role_id',
                openapi.IN_PATH,
                description="ID роли, которую необходимо назначить",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        request_body=GrantRoleSerializer,
        responses={
            200: openapi.Response(
                description="Операция успешно завершена",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, example="successes"),
                        'created': openapi.Schema(type=openapi.TYPE_BOOLEAN, description="Создана ли новая запись")
                    }
                )
            ),
            400: openapi.Response(
                description="Ошибка валидации или логики",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING,
                                                example="Эта роль уже назначена данному пользователю"),
                        'user_id': openapi.Schema(type=openapi.TYPE_ARRAY,
                                                  items=openapi.Items(type=openapi.TYPE_STRING),
                                                  description="Ошибки валидации поля user_id")
                    }
                )
            ),
            404: "Пользователь или Роль не найдены",
            401: "Не авторизован",
            403: "Недостаточно прав (adminpanel:manage)"
        },
        tags=['Администрирование']
    )
    def post(self, request, role_id):
        serializer = GrantRoleSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user_id = serializer.validated_data['user_id']

        user = get_object_or_404(User, id=user_id)
        role = get_object_or_404(Role, id=role_id)

        if UserRole.objects.filter(user=user, role=role).exists():
            return Response(
                {"error": "Эта роль уже назначена данному пользователю"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            obj, created = UserRole.objects.get_or_create(user=user, role=role)
            return Response({"status": "successes", "created": created}, status=status.HTTP_200_OK)
        except IntegrityError:
            return Response({"status": "already exists"}, status=status.HTTP_200_OK)


class AdminAddPermissionToRoleView(APIView):
    """
        Добавить permission к роли.
        Доступ: Требуется валидный JWT + Сессия в БД (401)
        и право 'adminpanel:manage' (403).
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [RequirePermission.as_perm("adminpanel", "manage")]

    @swagger_auto_schema(
        operation_summary="Добавление разрешения в роль",
        operation_description=(
                "Привязывает существующее разрешение к указанной роли. "
                "Формат поля 'permission' в теле запроса должен быть 'resource:action'."
        ),
        manual_parameters=[
            openapi.Parameter(
                'role_id',
                openapi.IN_PATH,
                description="ID роли, в которую добавляется разрешение",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        request_body=PermissionAddSerializer,
        responses={
            200: openapi.Response(
                description="Разрешение успешно добавлено",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={'status': openapi.Schema(type=openapi.TYPE_STRING, example="success")}
                )
            ),
            400: openapi.Response(
                description="Ошибка валидации или дублирования",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={'error': openapi.Schema(type=openapi.TYPE_STRING,
                                                        example="Это разрешение уже назначено данной роли")}
                )
            ),
            404: openapi.Response(
                description="Роль или разрешение не найдены",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={'error': openapi.Schema(type=openapi.TYPE_STRING, example="Разрешение не найдено")}
                )
            ),
            401: "Не авторизован",
            403: "Недостаточно прав",
            500: "Внутренняя ошибка сервера"
        },
        tags=['Администрирование']
    )
    def post(self, request, role_id):
        try:
            serializer = PermissionAddSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            role = get_object_or_404(Role, id=role_id)
            perm_code = serializer.validated_data['permission']  # пример: "adminpanel:delete"

            if not perm_code:
                raise ValidationError("Поле 'permission' не может быть пустым")
            if ':' not in perm_code:
                raise ValidationError("Поле 'permission' должно содержать двоеточие в формате 'resource:action'")

            res_name, action_name = perm_code.split(":", 1)
            perm = Permission.objects.get(resource__name=res_name, action__name=action_name)

            role_permission, created = RolePermission.objects.get_or_create(role=role, permission=perm)
            if not created:
                return Response({"error": "Это разрешение уже назначено данной роли"},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response({"status": "success"}, status=status.HTTP_200_OK)
        except (ValidationError, ObjectDoesNotExist, IntegrityError) as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Permission.DoesNotExist:
            return Response({"error": "Разрешение не найдено"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": "Внутренняя ошибка сервера"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
