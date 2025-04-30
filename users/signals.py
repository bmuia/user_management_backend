# users/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.core.signing import Signer
from .models import CustomUser

signer = Signer()

@receiver(post_save, sender=CustomUser)
def send_verification_email(sender, instance, created, **kwargs):
    if created and not instance.is_verified:
        token = signer.sign(instance.email)
        frontend_url = "http://localhost:5173/verify-email" 
        verify_url = f"{frontend_url}?token={token}"

        send_mail(
            subject="Verify your email",
            message=f"Click the link to verify your email: {verify_url}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[instance.email],
            fail_silently=False,
        )

