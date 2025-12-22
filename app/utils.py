import jwt
from datetime import datetime, timedelta, timezone as pytimezone
from django.conf import settings


def create_access_token(user, permissions: set[str], session_id, ttl_hours=12):
    now = datetime.now(tz=pytimezone.utc)

    payload = {
        "sub": str(user.id),
        'session_id': str(session_id),
        "email": user.email,
        "is_active": user.is_active,
        "permissions": list(permissions),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=ttl_hours)).timestamp()),
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET,
        algorithm="HS256"
    )
    return token


def get_user_permission_codes(user):
    codes = set()

    for ur in user.user_roles.select_related('role'):
        role = ur.role
        for rp in role.role_permissions.select_related(
                'permission__resource',
                'permission__action'
        ):
            perm = rp.permission
            codes.add(f"{perm.resource.name}:{perm.action.name}")

    return codes
