from django.contrib.auth.hashers import check_password, make_password
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import IsAuthenticated

from .models import MyUser
from .serializers import *


class RegisterUserView(CreateAPIView):
    serializer_class = RegisterUserSerializer


class LoginUserView(GenericAPIView):
    serializer_class = LoginUserSerializer

    def post(self, request, *args, **kwargs):
        serializer_obj = self.get_serializer(data=request.data)
        if serializer_obj.is_valid(): # valid serializer object
            user = self.authentication_user(serializer_obj.validated_data)
            # now data is valid so create token for user .
            refresh_token = RefreshToken.for_user(user) # create refresh token
            access_token = refresh_token.access_token # create access token
            return Response(
                {
                    'access_token': str(access_token),
                    'refresh_token': str(refresh_token)
                },
                status=status.HTTP_200_OK
            )
        return Response(serializer_obj.errors, status=status.HTTP_400_BAD_REQUEST)

    def authentication_user(self, validated_data):
        """ authentication user with email and password """
        email = validated_data.get('email')
        password = validated_data.get('password')
        try:
            user = MyUser.objects.get(email=email)
            if not check_password(password, user.password):
                raise AuthenticationFailed('email or password invalid !')
            return user
        except MyUser.DoesNotExist:
            raise AuthenticationFailed('email or password invalid !')


class RefreshTokenView(APIView):
    """ View for refresh token """
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


class ChangePasswordView(GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = (IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            data = serializer.validate_data
            old_pass, new_pass = data.get('old_password'), data.get('new_password')
            if check_password(old_pass, request.user.password): # check old passvord correct .
                user.set_password(new_pass) # set new password .
                user.save()
                return Response({'message': 'Update Your Password Successfully .'}, status=status.HTTP_200_OK)
            # show error if old password be incorrect .
            return Response({'error': 'The old password is wrong !'}, status=status.HTTP_400_BAD_REQUEST)
        # show error if invalid object serializer .
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
