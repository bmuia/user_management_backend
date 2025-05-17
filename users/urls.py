from django.urls import path
from .views import (
    LoginView,
    LogoutView,
    UserProfileList,
    VerifyAndRegisterView,  
    PasswordResetConfirmView,
    PasswordResetView,
    CurrentUserView,
    PreRegisterView,  
    AdminUserRegister,
    AdminUserUpdateView
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('logout/', LogoutView.as_view(), name='logout'),


    path('profiles/', UserProfileList.as_view(), name='user_profile'),
    path('verify-email/', VerifyAndRegisterView.as_view(), name='verify_email'), 
    path('pre-register/', PreRegisterView.as_view(), name='pre_register'), 
    path('reset-password/', PasswordResetView.as_view(), name='password_reset'),    
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    path('admin/register/user/',AdminUserRegister.as_view(), name='admin-register-user'),
    path('admin/<int:pk>/update/', AdminUserUpdateView.as_view(), name='update-user')
]
