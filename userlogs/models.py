from django.db import models
from django.contrib.auth import get_user_model
# Create your models here.

User = get_user_model()

class UserLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_logs', null=True, blank=True)
    action = models.CharField(max_length=255)
    email_snapshot = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    


    def __str__(self):
        return f"{self.user.username} - {self.action} - {self.timestamp}"
    

