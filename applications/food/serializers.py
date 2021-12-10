from rest_framework import serializers
from .models import *
from rest_framework.exceptions import ValidationError, APIException
from django.contrib.auth import authenticate
import re


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


class ChangePasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', ]


class ChangeProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        extra_kwargs = {
            'password': {"write_only": True}
        }

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


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = '__all__'


class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = '__all__'


class ContentSerializer(serializers.ModelSerializer):
    image = ImageSerializer(many=True)

    class Meta:
        model = Content
        fields = '__all__'


class ReviewSerializer(serializers.ModelSerializer):
    content = ContentSerializer(many=True)
    comment = CommentSerializer(many=True)

    class Meta:
        model = Review
        fields = '__all__'


class ReviewFoodSerializer(serializers.ModelSerializer):
    review = ReviewSerializer(many=True)

    class Meta:
        model = User
        fields = '__all__'


class HomepageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ['title', 'image_title', ]


class UpdateReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = '__all__'

    def update(self, instance, validated_data):
        for k, v in validated_data.items():
            setattr(instance, k, v)
        instance.save()
        return instance

    def validate(self, attrs):
        if re.findall("[^\s0-9a-zA-Z]", attrs['title']):
            raise APIException(detail="Only fill 0-9, a-z, A-Z and white space characters", code="FormatError")
        return attrs


class UpdateContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Content
        fields = '__all__'


class UpdateImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = '__all__'
