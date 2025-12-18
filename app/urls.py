from django.contrib.auth.views import LogoutView
from django.urls import path

from app.serializers import UserProfileSerializer
from app.views import RegisterView, LoginView,ListUser,MeView

urlpatterns = [
    path('register/', RegisterView.as_view(),name='register'),
    path('login/', LoginView.as_view(),name='login'),
    path('logout/', LogoutView.as_view(),name='logout'),
    path('users/', ListUser.as_view(),name='users'),
    path('me/', MeView.as_view(),name='me'),
    ]