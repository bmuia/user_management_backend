from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework import status,generics
from .serializers import MessageSerializer,NotificationSerializer
from .models import Message,Notification
from userlogs.utils import log_user_action
from django.utils import timezone



class ContactAdminView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            # Log the action
            log_user_action(request.user, 'Contacted admin')
            return Response({"message": "Message sent!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AdminMessageListView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        messages = Message.objects.all().order_by('-created_at')
        serializer = MessageSerializer(messages, many=True)
        return Response(serializer.data)

class AdminReplyView(APIView):
    permission_classes = [IsAdminUser]

    def post(self,request, message_id):
        try:
            message = Message.objects.get(id=message_id)
        except Message.DoesNotExist:
            return Response ({'error': 'Message does not exist'}, status=status.HTTP_404_NOT_FOUND)
        
        reply = request.data.get("reply")
        if not reply:
            return Response({"error": "Reply is required"}, status=status.HTTP_400_BAD_REQUEST)
        

        message.reply = reply
        message.replied_at = timezone.now()
        message.save()

        Notification.objects.create(
            user=message.user,
            message=message,
            content="You received a reply from the admin."

        )
        
        return Response({"message": "Reply sent successfully!"}, status=status.HTTP_200_OK)
    

class UserNotificationListView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')

