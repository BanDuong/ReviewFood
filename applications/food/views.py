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

            access_token = generate_access_token(user)
            refresh_token = generate_fresh_token(user)

            response = Response()
            response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)

            rd.set("refresh_token_" + user.username, refresh_token)

            serializer = LoginUserSerializer(instance=user)

            response.data = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": serializer.data,
            }
            return response

        except Exception as e:
            raise ErrLogin(entity="User", err=e)

    def get(self, request, *args, **kwargs):
        try:
            coockie_refresh_token = request.COOKIES.get('refresh_token').encode('utf-8')
            payload = jwt.decode(coockie_refresh_token, key=settings.REFRESH_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload.get('id'))
            redis_refresh_token = rd.get("refresh_token_" + user.username)
            if coockie_refresh_token == redis_refresh_token:
                serializer = LoginUserSerializer(user)
                return Response(data={"user": serializer.data})
            else:
                raise ValidationError(detail="Error Connection", code="ErrConnection")
        except Exception as e:
            raise ValidationError(detail="don't get information",code="GetInforError")

class LogoutUser(APIView):

    def post(self, request, *args, **kwargs):
        response = Response()
        all_token_in_redis = rd.keys()
        token_in_cookie = request.COOKIES.get('refresh_token')
        if token_in_cookie:
            for redis_key in all_token_in_redis:
                if rd.get(redis_key) == token_in_cookie.encode('utf-8'):
                    rd.delete(redis_key)
                    response.delete_cookie(key="refresh_token")
                    break

            response.data = {"result": "Log out successful"}
            return response
        else:
            response.data = {"response":"No any account logging"}
            return response
