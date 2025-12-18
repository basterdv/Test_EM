from django.urls import path

urlpatterns = [
    path('api/register', RegisterView.as_view()),
    path('api/login', LoginView.as_view()),
    ]