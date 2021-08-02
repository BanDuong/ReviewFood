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
from .token import generate_access_token, generate_fresh_token, generate_token
from django.conf import settings
import redis
import uuid
from .mail import verify_email, send_content_by_email
from django.contrib.auth import authenticate
from django.views import View

rd = redis.Redis(host="redis")


# -------------------------------------------Common------------------------------------------#

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
        except Exception as e:
            if type(e) == jwt.exceptions.ExpiredSignatureError:
                payload = jwt.decode(get_refresh_token, key=settings.REFRESH_KEY, algorithms=["HS256"])
                user = User.objects.get(id=payload.get('id'))
                access_token = generate_access_token(user)
                response.set_cookie(key='access_token', value=access_token, httponly=True)
                return response, user
            else:
                raise ValidationError(detail=e)


class ForgetPassword(APIView):

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get('email')
            if email:
                user = User.objects.get(email=email)
                if user:
                    new_pw = user.username + str(random.randint(10000, 1000000))
                    user.set_password(new_pw)
                    send_content_by_email(email, "forget password", "your new pass word: " + str(new_pw))
                    user.save()
                    return Response(data={"notice": "sent new password to your email. Check it now please!"})
                else:
                    raise ValidationError("User not exist")
            else:
                raise ValidationError("check your email request again")
        except Exception as e:
            raise ValidationError(e)


# ----------------------------------User-----------------------------------------------------------#

class CreateUser(APIView):

    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            if data.get('password') == data.get('re_password'):
                serializer = CreateUserSerializer(data=data)
                serializer.is_valid(raise_exception=True)
                code = random.randint(10000, 1000000)
                token = generate_token(data, code)
                # serializer.save()
                send_content_by_email(data.get('email'), "Verify your account",
                                      "token: " + str(token) + '\n' + 'code: ' + str(code),
                                      "http://localhost:8000/api/v1/verify_create_user/")
                # return Response(data=serializer.data, status=status.HTTP_200_OK)
                return Response(
                    data={"notice": "next to verify account: http://localhost:8000/api/v1/verify_create_user/"})
            else:
                raise ValidationError(detail="password wrong", code="PasswordWrong")
        except Exception as e:
            raise ErrCannotCreateEntity(entity="User", err=e)


class VerifyCreateUser(APIView):
    def post(self, request, *args, **kwargs):
        code = request.data.get('code')
        token = request.data.get('token')
        if code and token:
            payload = jwt.decode(token, key=settings.SECRET_KEY, algorithms=["HS256"])
            serializer = CreateUserSerializer(data=payload)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        else:
            raise ValidationError("No data request")


class LoginUser(APIView):

    def get(self, request, *args, **kwargs):
        return Response()

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
            new_password = user.username + str(random.randint(10000, 10000000))
            user.set_password(new_password)
            user.save()
            send_content_by_email(user.email, "Reset password",
                                  f"This's your password.\n {new_password} \nPlease change your password after login.")
            response.data = {"notice": "successfully reset"}
            return response
        except:
            raise ValidationError("User does not exist")


class UpdateUser(generics.UpdateAPIView):
    queryset = User.objects.all()

    def put(self, request, *args, **kwargs):
        try:
            data = request.data
            if data:
                response = check_token_user(request, "access_token_admin", "refresh_token_admin")[0]
                user = self.get_object()
                if user:
                    for k, value in data.items():
                        setattr(user, k, value)
                    user.save()
                    response.data = {"notice": "Changed user information successfully"}
                    return response
                else:
                    raise ValidationError(detail="user not exist")
            else:
                raise ValidationError(detail="No data upload. Check again!")
        except Exception as e:
            raise ValidationError(e)


class DeleteUser(generics.DestroyAPIView):
    queryset = User.objects.all()

    def delete(self, request, *args, **kwargs):
        response, user_admin = check_token_user(request, "access_token_admin", "refresh_token_admin")
        try:
            user = self.get_object()
            if user != user_admin:
                if user:
                    user.delete()
                    response.data = {"notice": "deleted successfully"}
                    return response
                else:
                    raise ValidationError("User does not exist")
            else:
                response.data = {"notice": "account logging in. Don't delete"}
                return response
        except Exception as e:
            raise ValidationError(e)


# ---------------------------------------UI-----------------------------------------#

class Test(APIView):

    def get(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        return render(request, template_name="food/base.html")


