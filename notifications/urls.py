# urls.py
from django.urls import path
from .views import ContactAdminView, AdminMessageListView

urlpatterns = [
    path('contact-admin/', ContactAdminView.as_view(), name='contact-admin'),
    path('admin/messages/', AdminMessageListView.as_view(), name='admin-messages'),
]
