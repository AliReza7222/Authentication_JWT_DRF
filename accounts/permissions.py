from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class IsAuthenticationJwt(BasePermission):

    def has_permission(self, request, view):
        cookies = request.COOKIES

        if 'access_token' not in cookies:
            return False

        jwt_authentication = JWTAuthentication()

        access_token = cookies.get('access_token')

        try:
            jwt_authentication.get_validated_token(access_token)

        except(InvalidToken, TokenError):
            return False

        return True
