from django.db import models
from django.contrib.auth import get_user_model


# Create your models here.
User = get_user_model()
class Message(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.user.username}"