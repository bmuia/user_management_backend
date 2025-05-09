from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class EmailBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            user = UserModel.objects.get(email__iexact=email)
            if user.check_password(password):
                return user
            else:
                return None
        except UserModel.DoesNotExist:
            return None
        except Exception as e:
            return None