from django.urls import path

from app.serializers import UserProfileSerializer
from app.views import RegisterView, LoginView, ListUser, MeView, DeleteMeView, LogoutView, AdminRolesView, \
    AdminGrantRoleView, AdminAddPermissionToRoleView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="API Documentation for TestEm",
        default_version='v1',
        description="Test description",
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)
urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/logout/', LogoutView.as_view(), name='logout'),

    path('api/users_list/', ListUser.as_view(), name='users'),
    path('api/me/', MeView.as_view(), name='me'),
    path('api/me_delete/', DeleteMeView.as_view(), name='delete_me'),

    path('admin/roles', AdminRolesView.as_view()),
    path('admin/roles/<int:role_id>/grant/', AdminGrantRoleView.as_view()),
    path('admin/roles/<int:role_id>/add-permission/', AdminAddPermissionToRoleView.as_view()),

    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
