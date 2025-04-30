from django.urls import path
from .views import welcome

urlpatterns = [
    path('', welcome.as_view(), name='welcome'),
]
