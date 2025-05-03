from django.urls import path
from .views import UserLogListView

urlpatterns = [
    path('admin/user-logs/', UserLogListView.as_view(), name='user-log-details')
]
