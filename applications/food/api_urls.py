from django.urls import path, include
from . import views

urlpatterns = [
    path('createuser/', views.CreateUser.as_view(), name="create_user"),
    path('login/', views.LoginUser.as_view(), name="login_user"),
    path('logout/', views.LogoutUser.as_view(), name="logout_user"),
]
