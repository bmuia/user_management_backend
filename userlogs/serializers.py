from rest_framework import serializers
from .models import UserLog

class UserLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserLog
        fields = ['id', 'user', 'action','email_snapshot', 'timestamp']
        read_only_fields = ['id', 'timestamp']
