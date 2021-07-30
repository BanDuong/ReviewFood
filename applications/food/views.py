import random
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
from .mail import verify_email, send_content_by_email
from django.contrib.auth import authenticate

# ----------------------------------User-----------------------------------------------------------#
rd = redis.Redis(host="redis")


def check_token_user(request, access_token, refresh_token):
    get_refresh_token = rd.get(refresh_token)
    get_access_token = request.COOKIES.get(access_token)
    if not get_access_token or not get_refresh_token:
        raise ValidationError(detail="Please Login", code="DontLogin")
    else:
        response = Response()
        try:
            payload = jwt.decode(get_access_token, key=settings.SECRET_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload.get('id'))
            return response, user
        except:
            payload = jwt.decode(get_refresh_token, key=settings.REFRESH_KEY, algorithms=["HS256"])
            user = User.objects.get(id=payload.get('id'))
            access_token = generate_access_token(user)
            response.set_cookie(key='access_token', value=access_token, httponly=True)
            return response, user


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
            email = request.data.get('email')
            password = request.data.get('password')

            user = authenticate(email=email, password=password)
            if user == None:
                raise ValidationError(detail="Check password or email again")
            else:
                response = Response()
                if request.COOKIES.get('access_token'):
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
        response, user = check_token_user(request, "access_token", "refresh_token")
        serializer = ProfileSerializer(user)
        response.data = {"user": serializer.data}
        return response


class ChangePasswordUser(APIView):

    def put(self, request, *args, **kwargs):
        if request.data:
            response, user = check_token_user(request, "access_token", "refresh_token")
            password = request.data.get('password')
            if user.check_password(password):
                new_password = request.data.get('new_password')
                renew_password = request.data.get('renew_password')
                if new_password == renew_password:
                    user.set_password(new_password)
                    user.save()
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
                response, user = check_token_user(request, "access_token", "refresh_token")
                for k, value in data.items():
                    setattr(user, k, value)
                user.save()
                verify_email(user.email)
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
            response.data = {"notice": "logged out successfully!"}
            return response
        else:
            return Response(data={"warning": "No any account logging"})


# ------------------------------------------Admin-------------------------------------------------------#

class LoginAdmin(APIView):
    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            user = authenticate(email=email, password=password)
            if user == None:
                raise ValidationError(detail="Check password or email again")
            else:
                response = Response()
                if (user.is_admin and user.is_staff) == True:
                    if request.COOKIES.get('access_token_admin'):
                        response.data = {"warning": "Account is already logged in. Don't try again!"}
                        return response
                    else:
                        access_token = generate_access_token(user)
                        refresh_token = generate_fresh_token(user)
                        response.set_cookie(key='access_token_admin', value=access_token, httponly=True)
                        rd.set("refresh_token_admin", refresh_token)
                        # rd.expire()
                        serializer = LoginUserSerializer(instance=user)

                        response.data = {
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "user": serializer.data,
                        }
                        return response
                else:
                    response.data = {"warning": "Not an admin account"}
                    return response
        except Exception as e:
            raise ErrLogin(entity="User", err=e)


class LogoutAdmin(APIView):

    def post(self, request, *args, **kwargs):
        if request.COOKIES.get("access_token_admin"):
            rd.delete("refresh_token_admin")
            response = Response()
            response.delete_cookie(key="access_token_admin")
            response.data = {"notice": "logged out successfully!"}
            return response
        else:
            return Response(data={"warning": "No any account logging"})


class ShowListUser(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = ProfileSerializer

    def get(self, request, *args, **kwargs):
        response = check_token_user(request, "access_token_admin", "refresh_token_admin")[0]  # only get response
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        response.data = {"user": serializer.data}
        return response


class RetrieveUser(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = ProfileSerializer

    def get(self, request, *args, **kwargs):
        response = check_token_user(request, "access_token_admin", "refresh_token_admin")[0]  # only get response
        try:
            user = self.get_object()
            serializer = self.get_serializer(user)
            response.data = {"user": serializer.data}
            return response
        except:
            raise ValidationError("User does not exist")


class ResetPasswordUser(generics.UpdateAPIView):
    queryset = User.objects.all()

    def put(self, request, *args, **kwargs):
        response = check_token_user(request, "access_token_admin", "refresh_token_admin")[0]  # only get response
        try:
            user = self.get_object()
            new_password = user.username + str(random.randint(10000,10000000))
            user.set_password(new_password)
            user.save()
            send_content_by_email(user.email, "Reset password", f"This's your password.\n {new_password} \nPlease change your password after login.")
            response.data = {"notice": "successfully reset"}
            return response
        except:
            raise ValidationError("User does not exist")
