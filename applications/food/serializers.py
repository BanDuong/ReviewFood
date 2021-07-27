from rest_framework import serializers
from .models import User
from rest_framework.exceptions import ValidationError
from django.contrib.auth import authenticate


class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "is_admin", "is_superuser", "is_staff", ]
        extra_kwargs = {
            'password': {"write_only": True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
            instance.save()
            return instance
        else:
            raise ValidationError(detail="password is required", code="PasswordRequirement")

    def validate_username(self, username):
        try:
            User.objects.get(username=username)
            raise ValidationError(detail="Username exist", code="EmailExist")
        except User.MultipleObjectsReturned:
            raise ValidationError(detail="Many similar usernames already exist", code="MultiUserNameExist")
        except User.DoesNotExist:
            return username
        except Exception as e:
            raise e

    def validate_email(self, email):
        try:
            User.objects.get(email=email)
            raise ValidationError(detail="Email exist", code="EmailExist")
        except User.MultipleObjectsReturned:
            raise ValidationError(detail="Many similar emails already exist", code="MultiEmailExist")
        except User.DoesNotExist:
            return email
        except Exception as e:
            raise e


class LoginUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "is_admin", "is_superuser", "is_staff", ]
        extra_kwargs = {
            'password': {"write_only": True}
        }

class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = '__all__'




