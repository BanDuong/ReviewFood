import random
from django.shortcuts import render, redirect
import logging
from common.paging import CustomPageNumberPagination20
from .models import *
from rest_framework.views import APIView
from rest_framework import generics
from common.errors import *
from .serializers import *
from rest_framework.response import Response
from rest_framework.exceptions import APIException, AuthenticationFailed, ValidationError
import jwt
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticatedOrReadOnly, IsAuthenticated
from .token import generate_access_token, generate_fresh_token, generate_token
from django.conf import settings
import redis
import uuid
from .mail import verify_email, send_content_by_email, send_report
from django.contrib.auth import authenticate
from django.views import View
from rest_framework.renderers import TemplateHTMLRenderer

log_info = logging.getLogger('log_info')
log_warn = logging.getLogger('log_warning')
rd = redis.Redis(host="redis")

class test(APIView):
    renderer_classes = [TemplateHTMLRenderer,]

    def get(self, request):
        data = Review.objects.all()
        return Response({'review': data}, template_name="food/base.html")

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
                response.set_cookie(key=access_token, value=generate_access_token(user), httponly=True)
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

            user = authenticate(username=email, password=password)
            if user == None:
                raise ValidationError(detail="Check password or email again")
            else:
                response = Response()
                if request.COOKIES.get('access_token'):
                    response.data = {"warning": "Account is already logged in. Don't try again!"}
                    response.status_code = status.HTTP_400_BAD_REQUEST
                    log_warn.warning("Account is already logged in.")
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
                    log_info.info("Loggin sucessful!")
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
            log_info.info("logged out successfully!")
            return response
        else:
            log_warn.warning("No any account logging")
            return Response(data={"warning": "No any account logging"}, status=status.HTTP_400_BAD_REQUEST)


# ------------------------------------------Admin-------------------------------------------------------#

class LoginAdmin(APIView):
    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get('email')
            password = request.data.get('password')

            user = authenticate(username=email, password=password)
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


# ---------------------------------------Management_DB-----------------------------------------#

# -----------------------------HOME------------------------------#

class SearchReview(generics.ListCreateAPIView):
    query = Content.objects.all()
    pagination_class = CustomPageNumberPagination20

    def post(self, request, *args, **kwargs):
        try:
            key = request.data.get('search')
            if key and self.query:
                data = []
                for content in self.query:
                    if key.lower() in content.heading.lower():
                        title = Review.objects.get(id=content.title_id).title
                        if len(data) == 0:
                            data.append(title)
                        else:
                            for d in data:
                                if title != d:
                                    data.append(title)
                return Response(data={'result': data})
            else:
                raise ValidationError("Data None")
        except Exception as e:
            raise ValidationError(e)


class ShowAllPost(generics.ListAPIView):
    queryset = Review.objects.filter(status=True)
    serializer_class = HomepageSerializer
    pagination_class = CustomPageNumberPagination20

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.filter_queryset(self.get_queryset())

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            raise ValidationError(e)


# -----------------------ADMIN---------------------------------#

class CheckPostReview(generics.ListCreateAPIView):
    queryset = Review.objects.filter(status=False)
    serializer_class = ReviewSerializer

    def get(self, request, *args, **kwargs):
        response = check_token_user(request, "access_token_admin", "refresh_token_admin")[0]
        try:
            queryset = self.filter_queryset(self.get_queryset())

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            response.data = {'data': serializer.data}
            return response
        except Exception as e:
            raise ValidationError(e)


class StatusPostReview(APIView):

    # serializer_class = ReviewSerializer

    def put(self, request, pk):
        response = check_token_user(request, "access_token_admin", "refresh_token_admin")[0]
        try:
            instance = Review.objects.get(id=pk)
            status = request.data.get('status')
            if instance.status == True:
                response.data = {"notice": "This review is activated. Don't activate again"}
                return response
            else:
                instance.status = True
                instance.save()
                response.data = {"notice": "Activated successfully"}
                return response
        except Exception as e:
            raise ValidationError(e)


class ShowAllUserPostReview(generics.ListAPIView):
    queryset = User.objects.prefetch_related('review').all()
    serializer_class = ReviewFoodSerializer

    def get(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token_admin", "refresh_token_admin")
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            raise ValidationError(e)

            # -----------------------------USER------------------------------#

class UserPostReview(APIView):

    def post(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            data = request.data
            if data:
                if not Review.objects.filter(title=data.get('title')):
                    r = Review(user=user, title=data.get('title'), image_title=data.get('image_title'))
                    r.save()
                else:
                    r = Review.objects.get(title=data.get('title'))
                if Content.objects.filter(heading=data.get('heading'), title_id=r.id):
                    raise ValidationError("Heading does exist")
                else:
                    c = Content(title=r, heading=data.get('heading'), content=data.get('content'))
                    c.save()
                    for img in data.getlist('image'):
                        i = Image(content=c, images=img)
                        i.save()
                    response.data = {"notice": "posted successfully"}
                    return response
            else:
                raise ValidationError("No data request")
        except Exception as e:
            raise ValidationError(e)


class UserDeleteReview(generics.DestroyAPIView):
    queryset = Review.objects.all()

    def delete(self, request, *args, **kwargs):
        response = check_token_user(request, "access_token", "refresh_token")[0]
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            response.data = {"notice": "deleted successfully"}
            response.status_code = status.HTTP_204_NO_CONTENT
            return response
        except Exception as e:
            raise ValidationError(e)

    def perform_destroy(self, instance):
        instance.delete()


class UserShowListReview(generics.ListAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer

    def get(self, request, *args, **kwargs):
        response = check_token_user(request, "access_token", "refresh_token")[0]
        try:
            queryset = self.filter_queryset(self.get_queryset())

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except Exception as e:
            raise ValidationError(e)


class UpdateReviewField(generics.RetrieveUpdateDestroyAPIView):
    queryset = Review.objects.all()
    serializer_class = UpdateReviewSerializer

    def get(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        except Exception as e:
            raise APIException(e)

    # update function into serializer

    # def put(self, request, *args, **kwargs):
    #     response, user = check_token_user(request, "access_token", "refresh_token")
    #     try:
    #         instance = self.get_object()
    #         for k, v in request.data.items():
    #             setattr(instance, k, v)
    #         instance.save()
    #         serializer = self.get_serializer(instance)
    #         response.data = {"update_data": serializer.data}
    #         return response
    #     except Exception as e:
    #         raise ValidationError(e)

    def delete(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(data={"notice": "deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            raise ValidationError(e)

    def perform_destroy(self, instance):
        instance.delete()


class UpdateContentField(generics.RetrieveUpdateDestroyAPIView):
    queryset = Content.objects.all()
    serializer_class = UpdateContentSerializer

    def get(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            instance = self.get_object()
            for k, v in request.data.items():
                setattr(instance, k, v)
            instance.save()
            serializer = self.get_serializer(instance)
            response.data = {"update_data": serializer.data}
            return response
        except Exception as e:
            raise ValidationError(e)

    def delete(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(data={"notice": "deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            raise ValidationError(e)

    def perform_destroy(self, instance):
        instance.delete()


class UpdateImagesField(generics.RetrieveUpdateDestroyAPIView):
    queryset = Image.objects.all()
    serializer_class = UpdateImageSerializer

    def get(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def put(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            instance = self.get_object()
            for k, v in request.data.items():
                setattr(instance, k, v)
            instance.save()
            serializer = self.get_serializer(instance)
            response.data = {"update_data": serializer.data}
            return response
        except Exception as e:
            raise ValidationError(e)

    def delete(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(data={"notice": "deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            raise ValidationError(e)

    def perform_destroy(self, instance):
        instance.delete()


class AddContentField(APIView):

    def post(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            data = request.data
            if not Content.objects.filter(heading=data.get("heading")):
                Content(heading=data.get("heading"), content=data.get("content"), title_id=data.get("title_id")).save()
                return Response(data={"notice": "Updated successfully"})
            else:
                raise ValidationError("This content does exist")
        except Exception as e:
            raise ValidationError(e)


class AddImageField(generics.CreateAPIView):

    def post(self, request, *args, **kwargs):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            for img in request.data.getlist("images"):
                Image(images=img, content_id=request.data.get("content_id")).save()
            return Response(data={"notice": "Updated successfully"})
        except Exception as e:
            raise ValidationError(e)

class UserReport(APIView):

    def post(self, request, *args, **kwargs):
        respone, user = check_token_user(request, "access_token", "refresh_token")
        try:
            send_report(user.email,request.data.get('subject'), request.data.get('content'), request.data.getlist('file_attach'), request.data.get('url'))
            respone.data = {"notice": "sent report to Admin"}
            return respone
        except Exception as e:
            raise ValidationError(e)


class UserComment(APIView):

    def post(self, request, pk):
        response, user = check_token_user(request, "access_token", "refresh_token")
        try:
            review = Review.objects.get(id=pk)
            if review:
                c = Comment(comments=request.data.get('comment'), review_id=pk)
                c.save()
                serializer = CommentSerializer(c)
                return Response(serializer.data)
            else:
                raise ValidationError("This review does not exist")
        except Exception as e:
            raise ValidationError(e)

