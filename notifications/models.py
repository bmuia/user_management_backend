from django.db import models
from django.contrib.auth import get_user_model


# Create your models here.
User = get_user_model()
class Message(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=True, blank=True)                  
    body = models.TextField()
    reply = models.TextField(null=True,blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    replied_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Message from {self.user.email}"
    
class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE,null=True, blank=True)  
    message = models.ForeignKey(Message, on_delete=models.CASCADE,null=True,blank=True)
    content = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "Notication sent!"
