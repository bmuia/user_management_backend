from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework import status
from .serializers import MessageSerializer
from .models import Message
from userlogs.utils import log_user_action



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

