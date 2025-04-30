from django.views import View
from django.http import JsonResponse

class welcome(View):
    def get(self, request):
        return JsonResponse({"message": "Welcome to the User Management System API!"})