from django.shortcuts import render
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.generics import CreateAPIView, GenericAPIView, UpdateAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import get_authorization_header



from .serializers import RegisterUserSerializer, LoginUserSerializer, ChangePasswordSerializer
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
            # return Response token access and refresh
            return Response({'access_token': str(access_token), 'refresh_token': str(refresh_token)},
                            status=status.HTTP_200_OK)

        return Response(serializer_obj.errors, status=status.HTTP_400_BAD_REQUEST)


# view for send refresh_token and get access_token
class RefreshTokenView(APIView):

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'error': 'Please provide a refresh token.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = refresh.access_token
            return Response({'access_token': str(access_token)}, status=status.HTTP_200_OK)

        except TokenError:
            return Response({'error': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)


# View for Change Password
class ChangePasswordView(UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated, ]

    def update(self, request, *args, **kwargs):
        user = request.user
        data = request.data
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            old_pass, new_pass = data.get('old_password'), data.get('new_password')
            if check_password(old_pass, user.password):
                hash_password = make_password(new_pass)
                user.password = hash_password
                user.save()
                return Response({'message': 'Update Your Password Successfully .'}, status=status.HTTP_200_OK)
            return Response({'error': 'The old password is wrong !'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
