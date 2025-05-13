from django.urls import path
from .views import (
    LoginView,
    LogoutView,
    UserProfileList,
    VerifyAndRegisterView,  
    PasswordResetConfirmView,
    PasswordResetView,
    UserProfileDetail,
    DeactivateAccountView,
    CookieTokenRefreshView,
    CurrentUserView,
    PreRegisterView,  
    ImpersonateUser,
    GoogleLoginView
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', CookieTokenRefreshView.as_view(), name='token_refresh'),
    path('google/', GoogleLoginView.as_view(), name='google-login'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('impersonate/', ImpersonateUser.as_view(), name='impersonate-noraml-user'),

    path('profiles/', UserProfileList.as_view(), name='user_profile'),
    path('profiles/<int:pk>/', UserProfileDetail.as_view(), name='user_profile_detail'), 
    path('verify-email/', VerifyAndRegisterView.as_view(), name='verify_email'), 
    path('pre-register/', PreRegisterView.as_view(), name='pre_register'), 
    path('reset-password/', PasswordResetView.as_view(), name='password_reset'),    
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('deactivate-account/', DeactivateAccountView.as_view(), name='deactivate_account'),
]
