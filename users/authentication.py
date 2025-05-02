from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed

class CookieJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Check for token in cookies
        token = request.COOKIES.get('access_token')

        if not token:
            return None  # No token, let the view decide if the user is unauthenticated

        try:
            # Try to validate the token
            validated_token = self.get_validated_token(token)

        except AuthenticationFailed as e:
            # Instead of raising, just return None to allow unauthenticated requests
            return None
        
        try:
            # Get the user from the validated token
            user = self.get_user(validated_token)
            return user, validated_token

        except AuthenticationFailed as e:
            # In case the user is not found, return None
            return None
