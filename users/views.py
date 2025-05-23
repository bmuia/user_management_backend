# Standard Imports
from datetime import datetime, timedelta

# Third-party Imports
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from django.core.mail import send_mail
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login
from django.core.signing import BadSignature, Signer, TimestampSigner
from django.db import transaction
from django.db.models import F
from django.shortcuts import get_object_or_404

# Local Imports
from .serializers import RegistrationSerializer, LoginSerializer, UserProfileSerializer, AdminUserUpdateSerializer

# Initialize User and Signer
User = get_user_model()
signer = Signer()

class LoginView(generics.CreateAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            user = authenticate(email=email, password=password)

            if user is not None:
                if not user.is_active:
                    return Response(
                        {'detail': 'User account is inactive.'},
                        status=status.HTTP_403_FORBIDDEN
                    )

                try:
                    refresh = RefreshToken.for_user(user)
                    access_token = str(refresh.access_token)
                    refresh_token = str(refresh)

                    response_data = {
                        'access': access_token,
                        'refresh': refresh_token,
                    }
                    return Response(response_data, status=status.HTTP_200_OK)

                except Exception as e:
                    return Response({'detail': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'detail': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response({'detail': 'Invalid or expired refresh token.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)

class PreRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')

            if User.objects.filter(email=email).exists():
                return Response({'error': 'A user with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

            signed_data = signer.sign_object(serializer.validated_data)
            expiration_time = timezone.now() + timedelta(hours=1)

            signed_data_with_expiration = signer.sign_object({
                'data': signed_data,
                'expiration': expiration_time.timestamp(),
            })

            verify_url = f"{settings.FRONTEND_URL}verify-email?token={signed_data_with_expiration}"

            send_mail(
                subject="Verify your email",
                message=f"Click the link to verify your email: {verify_url}\n\nLink expires in an hour.",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            return Response({'message': 'Verification email sent. Please check your inbox.'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyAndRegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({'error': 'Verification token is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            unsigned_token = signer.unsign_object(token)
            signed_data = unsigned_token.get('data')
            expiration_time = unsigned_token.get('expiration')
            if expiration_time < timezone.now().timestamp():
                return Response({'error': 'Token has expired.'}, status=status.HTTP_400_BAD_REQUEST)
            user_data = signer.unsign_object(signed_data)
            email = user_data.get('email')

            if not email:
                return Response({'error': 'Invalid verification token.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(email=email)
                if user.is_verified:
                    return Response({'message': 'This email has already been verified. Verification is only allowed once.'}, status=status.HTTP_200_OK)
                else:
                    user.is_verified = True
                    user.save()
                    return Response({'message': 'Email successfully verified.'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                serializer = RegistrationSerializer(data=user_data)
                if serializer.is_valid():
                    user = serializer.save()
                    user.is_verified = True
                    user.save()
                    return Response({'message': 'Email verified and registration successful.'}, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except BadSignature:
            return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data)

    def put(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request):
        request.user.is_active = False
        request.user.save()
        return Response({"message": "User account deactivated."}, status=status.HTTP_204_NO_CONTENT)

class UserProfileList(generics.ListAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        if request.user.is_staff:
            users = User.objects.filter(is_staff=False)
            serializer = self.serializer_class(users, many=True)
            return Response(serializer.data)
        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

class PasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            token = TimestampSigner().sign(user.email)
            reset_url = f"{settings.FRONTEND_URL}password-reset-confirm?token={token}"

            message = f'Click to reset your password: {reset_url}\n\nLink expires in 15 minutes.'

            send_mail(
                'Password Reset Request',
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'error': 'Failed to send password reset email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token')
        new_password = request.data.get('new_password')

        if not token or not new_password:
            return Response({'error': 'Token and new password are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = TimestampSigner().unsign(token, max_age=900)
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

        except (BadSignature, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)

class AdminUserRegister(generics.CreateAPIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            user.is_verified = True
            user.save()
            return Response({'message': 'User Created'}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminUserUpdateView(generics.UpdateAPIView):
    permission_classes = [IsAdminUser]
    queryset = User.objects.all()
    lookup_field = 'pk'
    serializer_class = AdminUserUpdateSerializer

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "User updated successfully."},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)