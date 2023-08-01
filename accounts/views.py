from django.shortcuts import render
from rest_framework.generics import CreateAPIView

from .serializers import RegisterUserSerializer


class RegisterUserView(CreateAPIView):
    serializer_class = RegisterUserSerializer
