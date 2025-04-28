from rest_framework import serializers
from .models import Message

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ['id', 'user', 'body', 'created_at']
        read_only_fields = ['id', 'created_at', 'user']
