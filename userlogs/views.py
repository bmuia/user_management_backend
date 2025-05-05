from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from .models import UserLog
from .serializers import UserLogSerializer

class UserLogListView(generics.ListAPIView):
    queryset = UserLog.objects.all().order_by('-timestamp')
    serializer_class = UserLogSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
