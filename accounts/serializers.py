from rest_framework import serializers
from django.contrib.auth.hashers import make_password

from .models import MyUser


class RegisterUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = MyUser
        fields = ['username', 'email', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate_password(self, value):
        if len(value) <= 6:
            raise serializers.ValidationError("Password must be 6 characters longer !")
        return value

    def validate(self, data):
        password, confirm = data['password'], data['confirm_password']
        if password != confirm:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        del validated_data['confirm_password']
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)


class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        new_password = data.get('new_password')
        confirm_new_password = data.get('confirm_new_password')
        if new_password != confirm_new_password:
            raise serializers.ValidationError("New Password do not match with confirm new password .")
        return data
