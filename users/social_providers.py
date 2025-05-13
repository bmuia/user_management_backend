# social_providers.py

import requests
from django.conf import settings
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()

class GoogleAuthProvider:
    @staticmethod
    def verify_token(id_token_str):
        try:
            # Verify token with Google's public keys
            id_info = id_token.verify_oauth2_token(
                id_token_str,
                google_requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )
            
            email = id_info.get("email")
            if not email:
                return None, "Email not provided by Google"

            return {
                "email": email,
                "first_name": id_info.get("given_name", ""),
                "last_name": id_info.get("family_name", ""),
                "picture": id_info.get("picture", ""),
                "verified": id_info.get("email_verified", False),
            }, None

        except ValueError as e:
            return None, str(e)

    @staticmethod
    def authenticate_or_create_user(google_data):
        email = google_data["email"]
        user, created = User.objects.get_or_create(email=email, defaults={
            "first_name": google_data["first_name"],
            "last_name": google_data["last_name"],
            "is_verified": google_data["verified"],
        })

        if not created and not user.is_verified and google_data["verified"]:
            user.is_verified = True
            user.save()

        return user

    @staticmethod
    def generate_tokens(user):
        refresh = RefreshToken.for_user(user)
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }
