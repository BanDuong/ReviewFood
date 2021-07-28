from django.urls import path
from . import views

urlpatterns = [
    path('createuser/', views.CreateUser.as_view(), name="create_user"),
    path('login/', views.LoginUser.as_view(), name="login_user"),  # login user
    path('logout/', views.LogoutUser.as_view(), name="logout_user"),  # logout user
    path('user/profile/', views.ProfileUser.as_view(), name="profile_user"),  # profile user
    path('user/change_password/', views.ChangePasswordUser.as_view(), name="change_password"),  # change password
    path('user/change_profile/', views.ChangeProfileUser.as_view(), name="change_profile"),  # change profile
]
