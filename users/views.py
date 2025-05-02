from datetime import datetime, timedelta
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from .serializers import RegistrationSerializer, LoginSerializer, UserProfileSerializer
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.core.signing import BadSignature, Signer, TimestampSigner
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone







User = get_user_model()

signer = Signer()

class RegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        data = request.data
        serializer = RegistrationSerializer(data=data)

        if serializer.is_valid():
            user = serializer.save()

            return Response({
                'message': 'Registration successful',         
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]
    # Optional: add throttling to limit login attempts
    # throttle_classes = [LoginThrottle]

    def post(self, request):
        login_data = request.data
        serializer = LoginSerializer(data=login_data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            user = authenticate(request, email=email, password=password)

            if user:
                # Update last login time
                user.last_login = timezone.now()
                user.save()

                # Generate tokens
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                # Build response
                response = Response({
                    'message': 'Login successful',

                }, status=status.HTTP_200_OK)

                # Set secure HttpOnly cookies
                expires_at = timezone.now() + timedelta(hours=6)
                response.set_cookie(
                    key='access_token',
                    value=access_token,
                    expires=expires_at,
                    secure=True,
                    httponly=True,
                    samesite='None',
                    path='/',
                )
                response.set_cookie(
                    key='refresh_token',
                    value=refresh_token,
                    expires=expires_at,
                    secure=True,
                    httponly=True,
                    samesite='None',
                    path='/',
                )

                return response

            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CookieTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            return Response({'error': 'Refresh token not provided'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = self.get_serializer(data={'refresh': refresh_token})

        try:
            serializer.is_valid(raise_exception=True)
        except (InvalidToken, TokenError):
            return Response({'error': 'Invalid or blacklisted refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

        access_token = serializer.validated_data['access']

        response = Response({'access': access_token}, status=status.HTTP_200_OK)

        # Optional: also set access_token as cookie
        response.set_cookie(
            key='access_token',
            value=access_token,
            expires=datetime.now(timezone.utc) + timedelta(hours=6),
            secure=True,
            httponly=True,
            samesite='None',
        )

        return response

    
class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)
    
    def put(self, request):
        user = request.user
        serializer = UserProfileSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"message": "User deleted."}, status=status.HTTP_204_NO_CONTENT)



class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):

        response = Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)

        # Access the refresh_token from the cookie
        refresh_token_cookie = request.COOKIES.get('refresh_token')

        if refresh_token_cookie:
            try:
                token = RefreshToken(refresh_token_cookie)
                token.blacklist()
            except TokenError:
                pass  

        print("Deleting cookies")
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        
        return response


class UserProfileList(generics.ListAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        if request.user.is_staff:
            queryset = User.objects.filter(is_staff=False)
            serializer = self.serializer_class(queryset, many=True)
            return Response(serializer.data)
        else:
            return Response({"detail": "You do not have permission to view all user profiles."},
                            status=status.HTTP_403_FORBIDDEN)


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

class UserProfileByID(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]


    def get(self, request, pk):
        try:
            user = self.get_object()
            serializer = self.serializer_class(user)
            if request.user.pk != user.pk and not request.user.is_staff:
               return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        try:
            user = self.get_object()
            serializer = self.serializer_class(user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, pk):
        try:
            user = self.get_object()
            user.delete()
            return Response({"message": "User deleted."}, status=status.HTTP_204_NO_CONTENT)
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

            # Create a TimestampSigner instance
            signer = TimestampSigner()

            # Sign the user's email with expiration time (15 minutes)
            token = signer.sign(user.email)

            frontend_url = f"{settings.FRONTEND_URL}/password-reset-confirm"
            reset_url = f"{frontend_url}?token={token}"

            # Message with expiration notice
            message = (
                f'Click the link to reset your password: {reset_url}\n\n'
                'Please note that this link will expire in 15 minutes.'
            )

            # Send the reset email
            send_mail(
                subject='Password Reset Request',
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )

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
            signer = TimestampSigner()
            email = signer.unsign(token, max_age=900)
            user = User.objects.get(email=email)
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)
        except (BadSignature, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)


class DeactivateAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        user.is_active = False
        user.save()
        return Response({'message': 'Account deactivated successfully'}, status=status.HTTP_200_OK)