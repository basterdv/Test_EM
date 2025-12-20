from django.contrib.auth import login
from rest_framework import serializers
from django.shortcuts import get_object_or_404
from .models import User
from .utils import get_user_permission_codes,create_access_token

class   UserListSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        model = User

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'id', 'first_name', 'last_name', 'email', 'is_active', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'is_active', 'created_at', 'updated_at')


class RegisterSerializer(serializers.Serializer):
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    patronymic = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    password_repeat = serializers.CharField(write_only=True)

    def validate(self, data):
        if data['password'] != data['password_repeat']:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        validated_data.pop('password_repeat')
        raw_password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(raw_password)
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = get_object_or_404(User, email=email)

        if not user.is_active:
            raise serializers.ValidationError({"detail": "Аккаунт удален (мягкое удаление)."})

        if not user.check_password(password):
            raise serializers.ValidationError({"detail": "Неверные учетные данные."})

        return {'user': user}

    def create(self, validated_data):
        user = validated_data['user']
        perms = get_user_permission_codes(user)
        token = create_access_token(user, perms)

        return {
            "token": token,
            "user": UserProfileSerializer(user).data,
        }



class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'patronymic', 'email')
