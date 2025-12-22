# EffectiveMobile Test ,  Auth Service (Django REST Framework + JWT + Session)

## Описание

Это тестовый backend на Django REST Framework + PostgreSQL, который демонстрирует:
- собственную аутентификацию пользователей по email/паролю;
- сессии на основе короткоживущего JWT (без Django SessionMiddleware и без встроенной auth-системы Django);
- собственную модель разграничения прав доступа (роли и разрешения);
- проверку доступа к ресурсам с корректными статусами 401 / 403;
- «мягкое удаление» пользователя (деактивация без физического удаления строки);
- административное API для управления ролями и правами.

---

## Архитектура 

### Схема базы данных 
1. User: Основная таблица пользователей. 
   - id: уникальный идентификатор пользователя.
   - first_name: имя пользователя.
   - last_name: фамилия пользователя.
   - middle_name: отчество пользователя.
   - email: адрес электронной почты пользователя.
   - password: зашифрованный пароль пользователя.
   - is_active: булево значение, указывающее, активен ли пользователь.
   

2. Role: Таблица ролей пользователей. 
   - id: уникальный идентификатор роли.
   - name: название роли (например, ‘admin’, ‘user’).
   
   
3. Resource: Таблица ресурсов 
    - id: уникальный идентификатор ресурса.
    - name: название ресурса (например, ‘adminpanel’, ‘reports’...).
   

4. Action: Таблица разрешенных действий.
    - id: уникальный идентификатор.
    - name: название действия (например, ("Чтение", "Обновление", ...).
    - description: описание


5. Permission: таблица прав доступа для конкретного ресурса. 
   - id: уникальный идентификатор.
   - resource: ресурс из связаной таблице Resource
   - action: название действия, из связаной таблице Action
   - description: описание
   
   
6. UserRole: таблица для связи между пользователями и ролями. 
   - id: уникальный идентификатор записи.
   - user_id: ссылка на пользователя.
   - role_id: ссылка на роль.
   

7. RolePermission: таблица для связи между ролями и правами. 
   - id: уникальный идентификатор записи.
   - role_id: ссылка на роль.
   - permission_id: ссылка на право.


8. Session:  Таблица сессий
    - id: уникальный идентификатор записи
   - user: ссылка на пользователя.
    - session_id: индификатор сессии
    - token_id: токен
   


## Цикл запроса
1. При регистрации клиенту выдается токен в котором прописанны права и индификатор ссесии которай хранится в базе данных
2. Клиент отправляет запрос с заголовком
   `Authorization: Bearer <jwt>`.
2. Кастомный `JWTAuthentication`:

   * декодирует токен с помощью `settings.JWT_SECRET` и `HS256`,
   * проверяет срок `exp`,
   * проверяет, что пользователь существует и `is_active == True`,
   * проверяет о соответствии сохраненной сессии
   * вешает на `request`:

     * `request.user_obj` — сам пользователь из БД,
     * `request.user_permissions` — множество строк вида `"resource:action"` (например, `"reports:update"`).
3. View указывает, какое право требуется:

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

`DELETE api/me_delete`:

* ставит `is_active = False` у текущего пользователя;
* удаляет сессию из БД
* старый токен тоже становится бесполезен, потому что аутентификация на каждом запросе проверяет `user.is_active`.
  После деактивации любая попытка использовать токен вернёт 401.

Запись при этом физически остаётся в БД

---


## Основные эндпоинты API

### 1. Регистрация

`POST api/register/`

Пример запроса:

```json
{
  "first_name": "Ярополк",
  "last_name": "Трофимов",
  "patronymic": "Савелий",
  "email": "demjan2022@example.com",
  "password": "7LWoIS",
  "password_repeat": "7LWoIS"
}
```

Ответ (201):

```json

{
  "message": "Пользователь demjan2022@example.com зарегистрирован успешно"
}
```

---

### 2. Логин

`POST /auth/login`

```json
{
  "email": "root@root.ru",
  "password": "root"
}
```

Ответ (200):

```json
{
  "token": "<JWT>",
  "user": {
    "id": 1,
    "first_name": "Pakghg",
    "last_name": "Yhserr",
    "email": "root@root.ru",
    "is_active": true,
    "created_at": "2025-12-21T15:44:37.513738Z",
    "updated_at": "2025-12-22T15:10:20.422287Z"
  }
}
```

Далее этот токен нужно передавать во всех приватных запросах:

```http
Authorization: Bearer <JWT>
```

---

### 3. Профиль текущего пользователя

`GET api/me/`

* Требует валидный JWT.
* Возвращает профиль текущего пользователя.

---

### 4. Мягкое удаление аккаунта

`DELETE api/me_delete`

* Ставит `is_active = false`.
* После этого логин перестаёт работать.
* Любые запросы со старым токеном → 401.

---

### 5. Бизнес-объекты (мок)

`GET /reports`

* Требуется право `reports:read`.
* Возвращает список фиктивных отчётов.

Варианты ответов:

* 401 — нет токена,
* 403 — токен есть, но права нет,
* 200 — доступ разрешён.

---

### 6. Обновление бизнес-объекта (мок)

`POST reports/<report_id>/update`

* Требуется право `reports:update`.
* Администратор может выдать права роли аналитика через админ-API.
---

### 7. Админка ролей

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
      "permissions": [
        "adminpanel:read",
        "adminpanel:update",        
        "reports:delete",
        "reports:manage"
      ]
    },
    {
      "role_id": 3,
      "role_name": "editor",
      "permissions": [        
        "reports:read",
        "reports:update"
      ]
    },
    {
      "role_id": 4,
      "role_name": "manager",
      "permissions": [
        "reports:read",       
        "reports:manage"
      ]
    },
    {
      "role_id": 2,
      "role_name": "user",
      "permissions": [
        "adminpanel:read"       
      ]
    }
  ]
}
```

---

### 8. Назначить роль пользователю

`POST /admin/roles/{role_id}/grant`

```json
{ "user_id": 2 }
```

Создаёт связь `UserRole(user=2, role={role_id})`.

---

### 9. Добавить permission к роли

`POST /admin/roles/{role_id}/add-permission`

```json
{ "permission": "reports:update" }
```

Добавляет `reports:update` к указанной роли через `RolePermission`.
После этого все пользователи с этой ролью получат право `reports:update` 
в НОВОМ токене (нужно перелогиниться, чтобы получить новый JWT с обновлённым списком `permissions`).

---

## Инициализация проекта

### 1. Установить зависимости 

```bash
pip install -r requirements.txt
```
Создать .env
Переменные окружения в `.env` должны быть заданы:

```env
# Основные настройки Django
DEBUG=True
SECRET_KEY=django-insecure-SECRET_KEY
SECRET_JWT_KEY=SECRET_JWT_KEY
ALLOWED_HOSTS=127.0.0.1,localhost

# Настройки базы данных (PostgreSQL)
USE_POSTGRESQL=True
POSTGRES_DB=test_em_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=1234
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
```

### 2. Миграции

```bash
python manage.py makemigrations
python manage.py migrate
```

### 3. Фикстуры

```bash
python manage.py loaddata app/fixtures/initial_data.json
```

Фикстуры создают:

* базовые действия `Action` (`read`, `update`, `manage`);
* ресурсы `Resource` (`reports`, `adminpanel`);
* права `Permission` (`reports:read`, `reports:update`, `adminpanel:manage`);
* роли `Role` (`admin`, `analyst`);
* связи ролей с правами;
* тестового пользователя `root@root.ru` с паролем `root`;
* назначение роли `admin` этому пользователю.

### 4. Запуск

```bash
python manage.py runserver
```

После этого:

* `POST /api/login` → получить токен
* `GET /api/me` → профиль текущего пользователя
* `GET /reports` → проверка `reports:read`
* `GET /admin/roles` → проверка `adminpanel:manage`