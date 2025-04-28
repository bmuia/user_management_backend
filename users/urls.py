from django.urls import path
from .views import (
    RegistrationView, 
    LoginView,
    LogoutView,
    UserProfileList,
    VerifyEmailView,
    PasswordResetConfirmView,
    PasswordResetView,UserProfileByID,
    UserProfileDetail,
    DeactivateAccountView,
    )



urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('profile/<int:pk>/', UserProfileByID.as_view(), name='user_profile_edit'),
    path('profiles/', UserProfileList.as_view(), name='user_profile'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('reset-password/', PasswordResetView.as_view(), name='password_reset'),    
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('deactivate-account/', DeactivateAccountView.as_view(), name='deactivate_account'),
]
