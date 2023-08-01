from django.shortcuts import render
from django.contrib.auth.hashers import check_password
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


from .serializers import RegisterUserSerializer, LoginUserSerializer
from .models import MyUser


class RegisterUserView(CreateAPIView):
    serializer_class = RegisterUserSerializer


class LoginUserView(GenericAPIView):
    serializer_class = LoginUserSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        serializer_obj = self.get_serializer(data=data)
        # valid serializer object
        if serializer_obj.is_valid():
            # authentication user
            email, password = data.get('email'), data.get('password')
            user_filter = MyUser.objects.filter(email=email)
            error_message = {'error': 'email or password invalid !'}
            if not user_filter.exists():
                return Response(error_message, status=status.HTTP_400_BAD_REQUEST)

            user = user_filter[0]
            check_password_user = check_password(password, user.password)

            if not check_password_user:
                return Response(error_message, status=status.HTTP_400_BAD_REQUEST)

            # now data is valid so create token for user .
            # create refresh token .
            refresh_token = RefreshToken.for_user(user)
            # create access token
            access_token = refresh_token.access_token
            # create a object Response for create cookies token but i don't know this work is good or no !
            response = Response({'message':f'Login successfully {user} .'}, status=status.HTTP_200_OK)
            response.set_cookie(key='access_token', value=access_token, httponly=True, secure=True, max_age=900)
            return response

        return Response(serializer_obj.errors, status=status.HTTP_400_BAD_REQUEST)
