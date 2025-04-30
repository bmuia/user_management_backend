from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser,AllowAny
from .serializers import RegistrationSerializer, LoginSerializer, UserProfileSerializer
from rest_framework_simplejwt. tokens import RefreshToken
from rest_framework.authentication import authenticate
from django.contrib.auth import get_user_model
from django.core.signing import BadSignature, Signer,TimestampSigner
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
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)



            return Response({
                'message': 'User successfully registered',
                'email': user.email ,
                'access': str(access_token),
                'refresh': str(refresh),
            }, status=status.HTTP_201_CREATED)  
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  
    
class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        data = request.data
        serializer = LoginSerializer(data=data)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(email=email, password=password)

            if user:

                user.last_login = timezone.now()
                user.save()
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)

                return Response({
                    'access': str(access_token),
                    'refresh': str(refresh),
                }, status=status.HTTP_200_OK)  
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)  
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LogoutView(APIView):
    def post(self,request):
        try:
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

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
    permission_classes = [IsAuthenticated,IsAdminUser]

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
        user = self.get_object()
        serializer = self.serializer_class(user)
        if request.user.pk != user.pk and not request.user.is_staff:
           return Response({"detail": "Permission denied."}, status=403)
        return Response(serializer.data)

    def put(self, request, pk):
        user = self.get_object()
        serializer = self.serializer_class(user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request, pk):
        user = self.get_object()
        user.delete()
        return Response({"message": "User deleted."}, status=status.HTTP_204_NO_CONTENT)
        
    def put(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            serializer = self.serializer_class(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class VerifyEmailView(APIView):
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

    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            
            # Create a signer instance
            signer = TimestampSigner()
            
            # Sign the user's email with expiration time (15 minutes)
            token = signer.sign(user.email)

            frontend_url = "http://localhost:5173/password-reset-confirm"
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

