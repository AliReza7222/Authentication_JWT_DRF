from django.urls import path

from .views import RegisterUserView, LoginUserView, RefreshTokenView, ChangePasswordView


urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh_token'),
    path('change_password/', ChangePasswordView.as_view(), name='change_password')
]
