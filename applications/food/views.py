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
                if request.COOKIES.get('refresh_token'):
                    response.data = {"warning": "Account is already logged in. Don't try again!"}
                    return response
                else:
                    access_token = generate_access_token(user)
                    refresh_token = generate_fresh_token(user)
                    response.set_cookie(key='access_token', value=access_token, httponly=True)
                    rd.set("refresh_token", refresh_token)
                    # rd.expire()
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
        get_refresh_token = rd.get("refresh_token")
        get_access_token = request.COOKIES.get("access_token")
        if not get_access_token or not get_refresh_token:
            raise ValidationError(detail="Please Login", code="DontLogin")
        else:
            response = Response()
            try:
                payload = jwt.decode(get_access_token, key=settings.SECRET_KEY, algorithms=["HS256"])
                user = User.objects.get(id=payload.get('id'))
                serializer = ProfileSerializer(user)
                response.data = {"user": serializer.data}
                return response
            except:
                payload = jwt.decode(get_refresh_token, key=settings.REFRESH_KEY, algorithms=["HS256"])
                user = User.objects.get(id=payload.get('id'))
                access_token = generate_access_token(user)
                response.set_cookie(key='access_token', value=access_token, httponly=True)
                serializer = ProfileSerializer(user)
                response.data = {"user": serializer.data}
                return response


class ChangePasswordUser(APIView):

    def put(self, request, *args, **kwargs):
        if request.data:
            get_refresh_token = rd.get("refresh_token")
            get_access_token = request.COOKIES.get("access_token")
            if not get_access_token or not get_refresh_token:
                raise ValidationError(detail="Please Login", code="DontLogin")
            else:
                response = Response()
                try:
                    payload = jwt.decode(get_access_token, key=settings.SECRET_KEY, algorithms=["HS256"])
                    user = User.objects.get(id=payload.get('id'))
                except:
                    payload = jwt.decode(get_refresh_token, key=settings.REFRESH_KEY, algorithms=["HS256"])
                    user = User.objects.get(id=payload.get('id'))
                    access_token = generate_access_token(user)
                    response.set_cookie(key='access_token', value=access_token, httponly=True)
                password = request.data.get('password')
                if user.check_password(password):
                    new_password = request.data.get('new_password')
                    renew_password = request.data.get('renew_password')
                    if new_password == renew_password:
                        user.set_password(new_password)
                        user.save()
                        # rd.delete("refresh_token")
                        # response.delete_cookie(key="access_token")
                        response.data = {"notice": "your password changed successfully"}
                        verify_email(user.email)
                        return response
                    else:
                        raise ValidationError(detail="check new password again", code="CheckNewPassword")
                else:
                    raise ValidationError(detail="Password wrong", code="PasswordWrong")
        else:
            raise ValidationError(detail="No data upload. Check again!")


class ChangeProfileUser(APIView):

    def put(self, request, *args, **kwargs):
        data = request.data
        if data:
            if request.data.get('password'):
                raise ValidationError(
                    detail="don't change the password in here, go to site: http://localhost:8000/api/v1/user/change_password/")
            else:
                get_refresh_token = rd.get("refresh_token")
                get_access_token = request.COOKIES.get("access_token")
                if not get_access_token or not get_refresh_token:
                    raise ValidationError(detail="Please Login", code="DontLogin")
                else:
                    response = Response()
                    try:
                        payload = jwt.decode(get_access_token, key=settings.SECRET_KEY, algorithms=["HS256"])
                        user = User.objects.get(id=payload.get('id'))
                    except:
                        payload = jwt.decode(get_refresh_token, key=settings.REFRESH_KEY, algorithms=["HS256"])
                        user = User.objects.get(id=payload.get('id'))
                        access_token = generate_access_token(user)
                        response.set_cookie(key='access_token', value=access_token, httponly=True)
                    for k, value in data.items():
                        setattr(user, k, value)
                    user.save()
                    verify_email(user.email)
                    # rd.delete("refresh_token")
                    # response.delete_cookie("access_token")
                    response.data = {"notice": "Update your profile successfully"}
                    return response
        else:
            raise ValidationError(detail="No data upload. Check again!")


class LogoutUser(APIView):

    def post(self, request, *args, **kwargs):
        if request.COOKIES.get("access_token"):
            rd.delete("refresh_token")
            response = Response()
            response.delete_cookie(key="access_token")
            response.data = {"notice": "deleted successfully!"}
            return response
        else:
            return Response(data={"warning": "No any account logging"})

# ------------------------------------------Admin-------------------------------------------------------#
