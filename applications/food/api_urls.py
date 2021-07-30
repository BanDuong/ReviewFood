from django.urls import path
from . import views

urlpatterns = [
    # --------------------------------User---------------------------------------------------------#

    path('createuser/', views.CreateUser.as_view(), name="create_user"),
    path('login/', views.LoginUser.as_view(), name="login_user"),  # login user
    path('logout/', views.LogoutUser.as_view(), name="logout_user"),  # logout user
    path('user/profile/', views.ProfileUser.as_view(), name="profile_user"),  # profile user
    path('user/change_password/', views.ChangePasswordUser.as_view(), name="change_password"),  # change password
    path('user/change_profile/', views.ChangeProfileUser.as_view(), name="change_profile"),  # change profile

    # ---------------------------------ADMIN--------------------------------------------------------------------#

    path('admin/login/', views.LoginAdmin.as_view(), name="login_admin"),  # login admin
    path('admin/logout/', views.LogoutAdmin.as_view(), name="logout_admin"),  # logout admin
    path('admin/listusers/', views.ShowListUser.as_view(), name="list_users"),  # show list users
    path('admin/retrieve/user/<int:pk>', views.RetrieveUser.as_view(), name="retrieve_users"),  # Retrieve each user
    path('admin/reset_password/<int:pk>', views.ResetPasswordUser.as_view(), name="reset_password_users"), # Reset password user
]
