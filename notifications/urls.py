# urls.py
from django.urls import path
from .views import ContactAdminView, AdminMessageListView,AdminReplyView,UserNotificationListView

urlpatterns = [
    path('contact-admin/', ContactAdminView.as_view(), name='contact-admin'),
    path('admin/messages/', AdminMessageListView.as_view(), name='admin-messages'),
    path('admin/messages/<int:message_id>/reply/', AdminReplyView.as_view(), name='admin-reply'),
    path('messages/', UserNotificationListView.as_view(),name='user-notifcations')

]
