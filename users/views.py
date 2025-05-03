from datetime import datetime, timedelta
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from .serializers import RegistrationSerializer, LoginSerializer, UserProfileSerializer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import authenticate, get_user_model
from django.core.signing import BadSignature, Signer, TimestampSigner
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from userlogs.utils import log_user_action

User = get_user_model()
signer = Signer()


class RegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            log_user_action(user, 'User registered', request)
            return Response({'message': 'Registration successful'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, email=email, password=password)
            if user:
                user.last_login = timezone.now()
                user.save()

                log_user_action(user, 'User logged in', request)

                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                response = Response({'message': 'Login successful'}, status=status.HTTP_200_OK)

                expires_at = timezone.now() + timedelta(hours=6)
                response.set_cookie('access_token', access_token, expires=expires_at, secure=False, httponly=True, samesite='Lax', path='/')
                response.set_cookie('refresh_token', refresh_token, expires=expires_at, secure=False, httponly=True, samesite='Lax', path='/')
                return response

            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response({'error': 'Refresh token not provided'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = self.get_serializer(data={'refresh': refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
        except (InvalidToken, TokenError):
            return Response({'error': 'Invalid or blacklisted refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

        access_token = serializer.validated_data['access']
        response = Response({'access': access_token}, status=status.HTTP_200_OK)
        response.set_cookie('access_token', access_token, expires=datetime.now(timezone.utc) + timedelta(hours=6), secure=True, httponly=True, samesite='None')
        return response


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        log_user_action(request.user, 'User profile viewed', request)
        return Response(serializer.data)

    def put(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        log_user_action(request.user, 'User profile updated', request)
        return Response(serializer.data)

    def delete(self, request):
        log_user_action(request.user, 'User account deleted', request)
        request.user.delete()
        return Response({"message": "User deleted."}, status=status.HTTP_204_NO_CONTENT)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        response = Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass

        log_user_action(request.user, 'User logged out', request)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response


class UserProfileList(generics.ListAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        if request.user.is_staff:
            users = User.objects.filter(is_staff=False)
            serializer = self.serializer_class(users, many=True)
            return Response(serializer.data)
        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)


class UserProfileDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, pk):
        try:
            user = self.get_object()
            serializer = self.serializer_class(user)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.GET.get('token')
        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            email = signer.unsign(token)
            user = User.objects.get(email=email)
            if user.is_verified:
                return Response({'message': 'Email is already verified'}, status=status.HTTP_400_BAD_REQUEST)

            user.is_verified = True
            user.save()
            log_user_action(user, 'Email verified', request)
            return Response({'message': 'Email verified successfully'}, status=status.HTTP_200_OK)

        except (BadSignature, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            token = TimestampSigner().sign(user.email)
            reset_url = f"{settings.FRONTEND_URL}/password-reset-confirm?token={token}"

            message = f'Click to reset your password: {reset_url}\n\nLink expires in 15 minutes.'

            send_mail(
                'Password Reset Request',
                message,
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            log_user_action(user, 'Password reset email sent', request)
            return Response({'message': 'Password reset email sent'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)


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
            log_user_action(user, 'Password reset confirmed', request)
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

        except (BadSignature, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)


class DeactivateAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.user.is_active = False
        request.user.save()
        log_user_action(request.user, 'Account deactivated', request)
        return Response({'message': 'Account deactivated successfully'}, status=status.HTTP_200_OK)
