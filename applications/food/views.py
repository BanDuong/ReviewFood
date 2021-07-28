import uuid

from django.shortcuts import render, redirect
from .models import User
from rest_framework.views import APIView
from rest_framework import generics
from common.errors import *
from .serializers import *
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed, ValidationError
import jwt
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly, IsAuthenticated
from .token import generate_access_token, generate_fresh_token
from django.conf import settings
import redis
import uuid
from .mail import verify_email
from django.contrib.auth import authenticate

# ----------------------------------User-----------------------------------------------------------#
rd = redis.Redis(host="redis")


def process_refresh_token(request):
    pass


class CreateUser(APIView):

    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            if data.get('password') == data.get('re_password'):
                serializer = CreateUserSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                verify_email(data.get('email'))
                return Response(data=serializer.data, status=status.HTTP_200_OK)
            else:
                raise ValidationError(detail="password wrong", code="PasswordWrong")
        except Exception as e:
            raise ErrCannotCreateEntity(entity="User", err=e)


class LoginUser(APIView):

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get('username')
            password = request.data.get('password')

            user = authenticate(username=email, password=password)
            if user == None:
                raise ValidationError(detail="Check password or username again")
            else:
                response = Response()
                if request.COOKIES.get('refresh_token_' + str(user.id)):
                    response.data = {"warning": "Account is already logged in. Don't try again!"}
                    return response
                else:
                    access_token = generate_access_token(user)
                    refresh_token = generate_fresh_token(user)
                    response.set_cookie(key='refresh_token_' + str(user.id), value=refresh_token, httponly=True)
                    rd.set("refresh_token_" + str(user.id), refresh_token)

                    serializer = LoginUserSerializer(instance=user)

                    response.data = {
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "user": serializer.data,
                    }
                    return response
        except Exception as e:
            raise ErrLogin(entity="User", err=e)


class ProfileUser(APIView):
    def get(self, request, *args, **kwargs):
        try:
            list_key_token = rd.keys()
            for key in list_key_token:
                if request.COOKIES.get(key.decode('utf-8')):
                    payload = jwt.decode(request.COOKIES.get(key.decode('utf-8')).encode('utf-8'),
                                         key=settings.REFRESH_KEY, algorithms=["HS256"])
                    user = User.objects.get(id=payload.get('id'))
                    serializer = ProfileSerializer(user)
                    return Response(data={"user": serializer.data})
                    break
            else:
                raise ValidationError(detail="Account logged out")
        except Exception as e:
            raise ValidationError(detail="don't get information", code="GetInforError")


class ChangePasswordUser(APIView):

    def put(self, request, *args, **kwargs):
        try:
            list_key_token = rd.keys()
            for key in list_key_token:
                if request.COOKIES.get(key.decode('utf-8')):
                    payload = jwt.decode(request.COOKIES.get(key.decode('utf-8')).encode('utf-8'),
                                         key=settings.REFRESH_KEY, algorithms=["HS256"])
                    user = User.objects.get(id=payload.get('id'))
                    password = request.data.get('password')
                    if user.check_password(password):
                        new_password = request.data.get('new_password')
                        renew_password = request.data.get('renew_password')
                        if new_password == renew_password:
                            user.set_password(new_password)
                            user.save()
                            return Response(data={"notice": "password changed successfully"})
                        else:
                            raise ValidationError(detail="check new password again", code="CheckNewPassword")
                    else:
                        raise ValidationError(detail="Password wrong", code="PasswordWrong")
        except Exception as e:
            raise ValidationError(detail="Can't Update password", code="UpdatePasswordError")


class ChangeProfileUser(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ChangeProfileSerializer

    def update(self, request, *args, **kwargs):
        try:
            if request.data.get('password'):
                raise ValidationError(detail="sorry! You can't change password in this site!")
            else:
                user = self.get_object()
                serializer = self.get_serializer(user, data=request.data)
                serializer.is_valid(raise_exception=True)
                serializer.save()
                user.save()
                return Response(serializer.data)
        except Exception as e:
            raise ErrCannotUpdateEntity(entity="User", err=e)


class LogoutUser(APIView):

    def post(self, request, *args, **kwargs):
        response = Response()
        list_key_token = rd.keys()
        for key in list_key_token:
            if request.COOKIES.get(key.decode('utf-8')):
                rd.delete(key)
                response.delete_cookie(key=key.decode('utf-8'))
                response.delete_cookie(key='csrftoken')
                response.data = {"result": "Log out successful"}
                return response
                break
        else:
            response.data = {"response": "No any account logging"}
            # return redirect('../login/')
            return response

# ------------------------------------------Admin-------------------------------------------------------#
