from django.urls import path
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from django.conf import settings
from django.conf.urls.static import static

from app.views import RegisterView, LoginView, ListUser, MeView, DeleteMeView, LogoutView, AdminRolesView, \
    AdminGrantRoleView, AdminAddPermissionToRoleView, ReportsListView, ReportsUpdateView

schema_view = get_schema_view(
    openapi.Info(
        title="API Documentation for TestEm",
        default_version='v1.1.2',
        description="Тестовое Задание для Effective Mobile",
        terms_of_service="https://disk.360.yandex.ru/i/VtbjR6_G5s8MeQ",
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

    path('reports', ReportsListView.as_view(),name='reports'),
    path('reports/<int:report_id>/update', ReportsUpdateView.as_view(),name='update_reports'),

    path('admin/roles', AdminRolesView.as_view(),name='admin_roles'),
    path('admin/roles/<int:role_id>/grant/', AdminGrantRoleView.as_view(),name='admin_grant_role'),
    path('admin/roles/<int:role_id>/add-permission/', AdminAddPermissionToRoleView.as_view(),name='admin_add_permission'),

    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
