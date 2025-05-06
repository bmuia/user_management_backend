# urls.py
from django.urls import path
from .views import ContactAdminView, AdminMessageListView,AdminRespondMessageView

urlpatterns = [
    path('contact-admin/', ContactAdminView.as_view(), name='contact-admin'),
    path('admin/messages/', AdminMessageListView.as_view(), name='admin-messages'),
    path('admin/reply/', AdminRespondMessageView.as_view(), name='admin-respond-message'),
]
