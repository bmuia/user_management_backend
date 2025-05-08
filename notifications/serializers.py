from rest_framework import serializers
from .models import Message, Notification


class MessageSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = Message
        fields = ['id', 'user', 'user_email', 'body', 'created_at','reply','replied_at']
        read_only_fields = ['id', 'created_at', 'user','replied_at']


class NotificationSerializer(serializers.ModelSerializer):
    message_sent = serializers.CharField(source='message.body', read_only=True)
    admin_message = serializers.CharField(source='message.reply', read_only=True)
    was_created_at = serializers.DateTimeField(source='message.created_at',read_only=True)
    class Meta:
        model = Notification
        fields = ['id', 'content','message_sent','admin_message', 'created_at','was_created_at']
