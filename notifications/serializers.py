from rest_framework import serializers
from .models import Message


class MessageSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'user', 'user_email', 'body', 'created_at']
        read_only_fields = ['id', 'created_at', 'user']
