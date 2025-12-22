# RBAC Auth Service (Django REST Framework + JWT)

## Что это

Это учебно-боевой backend на Django REST Framework + PostgreSQL, который демонстрирует:
- собственную аутентификацию пользователей по email/паролю;
- сессии на основе короткоживущего JWT (без Django SessionMiddleware и без встроенной auth-системы Django);
- собственную модель разграничения прав доступа (RBAC: роли и разрешения);
- проверку доступа к ресурсам с корректными статусами 401 / 403;
- «мягкое удаление» пользователя (деактивация без физического удаления строки);
- административное API для управления ролями и правами в рантайме.

Важный момент: проект намеренно **НЕ использует** `django.contrib.auth`, `django.contrib.auth.models.User`, `django.contrib.auth.models.Permission`, `IsAuthenticated`, `SessionAuthentication` и т.д.  
Все сущности (пользователь, роль, доступы) реализованы вручную.

---

## Архитектура авторизации

### Термины
- **User** — человек (имя, почта, пароль в хэше, флаг активности).
- **Role** — «набор прав» (например, `admin`, `analyst`).
- **Permission** — конкретное действие над конкретным ресурсом. Хранится как `resource:action`, например `reports:update`.
- **JWT access token** — выдаётся при логине. Содержит:
  - `sub` — ID пользователя,
  - `email`,
  - `is_active`,
  - `permissions` — список прав пользователя на момент логина,
  - сроки жизни (`iat`, `exp`).

### Почему JWT, а не таблица сессий
- Stateless: сервер не хранит активные сессии.
- Легко проверить токен в любом сервисе.
- Хорошо видно на защите.

Компромисс: если администратор поменяет пользователю роли/права, уже выданный токен об этом не узнает. Пользователь должен перелогиниться, чтобы получить обновлённый набор `permissions`. Это осознанный минус stateless-дизайна.

---

## RBAC-модель

Система прав построена как классический RBAC:

```text
User --(многие-ко-многим)--> Role --(многие-ко-многим)--> Permission
Permission = Resource + Action
````

* **Resource** — логическая область системы (`"reports"`, `"adminpanel"`, `"users"` ...).
* **Action** — тип разрешённого действия (`"read"`, `"update"`, `"manage"` ...).

Одна Permission = пара (`Resource`, `Action`):

* Resource = `reports`
* Action  = `update`
* Код разрешения = `reports:update`

Примеры:

* Роль `admin` имеет `adminpanel:manage`, `reports:read`, `reports:update`.
* Роль `analyst` имеет только `reports:read`.

---

## Жизненный цикл запроса

1. Клиент отправляет запрос с заголовком
   `Authorization: Bearer <jwt>`.
2. Кастомный `JWTAuthentication`:

   * декодирует токен с помощью `settings.JWT_SECRET` и `HS256`,
   * проверяет срок `exp`,
   * проверяет, что пользователь существует и `is_active == True`,
   * вешает на `request`:

     * `request.user_obj` — сам пользователь из БД,
     * `request.user_permissions` — множество строк вида `"resource:action"` (например, `"reports:update"`).
3. Вьюха указывает, какое право требуется:

   ```python
   permission_classes = [RequirePermission.as_perm("reports", "update")]
   ```
4. Кастомный `RequirePermission` делает проверку:

   * если токен невалидный или отсутствует → 401 Unauthorized;
   * если пользователь есть, но прав недостаточно → 403 Forbidden;
   * иначе — доступ разрешён.

Таким образом выполняется требование:

* 401 — «пользователь не аутентифицирован»;
* 403 — «пользователь аутентифицирован, но не авторизован».

---

## Мягкое удаление пользователя

`DELETE /me/delete`:

* ставит `is_active = False` у текущего пользователя;
* пользователь сразу теряет возможность логиниться;
* старый токен тоже становится бесполезен, потому что аутентификация на каждом запросе проверяет `user.is_active`.
  После деактивации любая попытка использовать токен вернёт 401.

Запись при этом физически остаётся в базе (для аудита и истории).

---

## Основные модели (упрощённо)

* `User`
  `email`, `password_hash`, `first_name`, `last_name`, `patronymic`, `is_active`, `created_at`, `updated_at`.

* `Role`
  `name` (например, `"admin"`, `"analyst"`), `description`.

* `UserRole`
  связь многие-ко-многим между User ↔ Role.

* `Resource`
  `name` (`"reports"`, `"adminpanel"`), `description`.

* `Action`
  `name` (`"read"`, `"update"`, `"manage"`), `description`.

* `Permission`
  `(resource, action)` → код `"resource:action"`.

* `RolePermission`
  связь многие-ко-многим между Role ↔ Permission.

### Важно

Нет модели `Session`.
JWT выступает в роли сессии.

---

## Основные эндпоинты API

### 1. Регистрация

`POST /auth/register`

Пример запроса:

```json
{
  "first_name": "Алиса",
  "last_name": "Кэрол",
  "patronymic": "Льюисовна",
  "email": "alice@wonderland.com",
  "password": "123456",
  "password_repeat": "123456"
}
```

Ответ (201):

```json
{
  "id": 2,
  "first_name": "Алиса",
  "last_name": "Кэрол",
  "patronymic": "Льюисовна",
  "email": "alice@wonderland.com",
  "is_active": true,
  "created_at": "...",
  "updated_at": "..."
}
```

---

### 2. Логин

`POST /auth/login`

```json
{
  "email": "admin@wonderland.com",
  "password": "123456"
}
```

Ответ (200):

```json
{
  "token": "<JWT>",
  "user": {
    "id": 1,
    "first_name": "Администратор",
    "last_name": "Системы",
    "email": "admin@wonderland.com",
    "is_active": true,
    "created_at": "...",
    "updated_at": "..."
  }
}
```

Далее этот токен нужно передавать во всех приватных запросах:

```http
Authorization: Bearer <JWT>
```

---

### 3. Профиль текущего пользователя

`GET /me`

* Требует валидный JWT.
* Возвращает профиль текущего пользователя.

Ошибки:

* нет/битый токен → 401.

---

### 4. Обновление профиля

`PATCH /me`

Позволяет менять, например, имя или email.

Ошибки:

* нет токена → 401.

---

### 5. Мягкое удаление аккаунта

`DELETE /me/delete`

* Ставит `is_active = false`.
* После этого логин перестаёт работать.
* Любые запросы со старым токеном → 401.

---

### 6. Бизнес-объекты (мок)

`GET /reports`

* Требуется право `reports:read`.
* Возвращает список фиктивных отчётов.

Варианты ответов:

* 401 — нет токена,
* 403 — токен есть, но права нет,
* 200 — доступ разрешён.

---

### 7. Обновление бизнес-объекта (мок)

`POST /reports/<id>/update`

* Требуется право `reports:update`.
* По умолчанию у аналитика этого права нет, у админа есть.
* Администратор может выдать права роли аналитика через админ-API.

---

### 8. Админка ролей

`GET /admin/roles`

* Требуется право `adminpanel:manage`.
* Возвращает список ролей и их прав.

Пример ответа:

```json
{
  "roles": [
    {
      "role_id": 1,
      "role_name": "admin",
      "permissions": ["reports:read", "reports:update", "adminpanel:manage"]
    },
    {
      "role_id": 2,
      "role_name": "analyst",
      "permissions": ["reports:read"]
    }
  ]
}
```

---

### 9. Назначить роль пользователю

`POST /admin/roles/{role_id}/grant`

```json
{ "user_id": 2 }
```

Создаёт связь `UserRole(user=2, role={role_id})`.

---

### 10. Добавить permission к роли

`POST /admin/roles/{role_id}/add-permission`

```json
{ "permission": "reports:update" }
```

Добавляет `reports:update` к указанной роли через `RolePermission`.
После этого все пользователи с этой ролью получат право `reports:update` в НОВОМ токене (нужно перелогиниться, чтобы получить новый JWT с обновлённым списком `permissions`).

---

## Инициализация проекта

### 1. Установить зависимости через Poetry

```bash
poetry install 
# poetry install --with postgres - для использования PostgreSQL вместо SQLite
poetry run python manage.py migrate
```

Для PostgreSQL следующие переменные окружения в `.env` должны быть заданы:

```env
POSTGRES_DB=rbac_demo
POSTGRES_USER=rbac_user
POSTGRES_PASSWORD=rbac_pass
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
```

если они не заданы - будет использоваться локальная база SQLite

### 2. Миграции

```bash
poetry run python manage.py makemigrations
poetry run python manage.py migrate
```

### 4. Фикстуры

```bash
poetry run python manage.py loaddata emauth/fixtures/initial_data.json
```

Фикстуры создают:

* базовые действия `Action` (`read`, `update`, `manage`);
* ресурсы `Resource` (`reports`, `adminpanel`);
* права `Permission` (`reports:read`, `reports:update`, `adminpanel:manage`);
* роли `Role` (`admin`, `analyst`);
* связи ролей с правами;
* тестового пользователя `admin@wonderland.com` с паролем `123456`;
* назначение роли `admin` этому пользователю.

### 5. Запуск

```bash
poetry run python manage.py runserver
```

После этого:

* `POST /auth/login` → получить токен
* `GET /me` → профиль текущего пользователя
* `GET /reports` → проверка `reports:read`
* `GET /admin/roles` → проверка `adminpanel:manage`