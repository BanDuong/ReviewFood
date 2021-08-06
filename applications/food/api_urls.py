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
    path('verify_create_user/', views.VerifyCreateUser.as_view(), name="verify_create_user"),  # verify code create user
    path('forget_password/', views.ForgetPassword.as_view(), name="forget_password"),  # forget_password
    path('user/report/', views.UserReport.as_view(), name="report"), # report

    # ---------------------------------ADMIN--------------------------------------------------------------------#

    path('admin/login/', views.LoginAdmin.as_view(), name="login_admin"),  # login admin
    path('admin/logout/', views.LogoutAdmin.as_view(), name="logout_admin"),  # logout admin
    path('admin/listusers/', views.ShowListUser.as_view(), name="list_users"),  # show list users
    path('admin/retrieve/user/<int:pk>', views.RetrieveUser.as_view(), name="retrieve_users"),  # Retrieve each user
    path('admin/reset_password/<int:pk>', views.ResetPasswordUser.as_view(), name="reset_password_users"),  # Reset password user
    path('admin/delete_user/<int:pk>', views.DeleteUser.as_view(), name="delete_users"),  # Delete user
    path('admin/update_user/<int:pk>', views.UpdateUser.as_view(), name="update_user"),  # Update user
    path('admin/check_post_review/', views.CheckPostReview.as_view(), name="check_post_review"),  # Check status Post Review
    path('admin/status_post_review/<int:pk>', views.StatusPostReview.as_view(), name="status_post_review"),  # Status Post Review

    #---------------------------------DB---------------------------------------------------------#
    path('admin/all/', views.ShowAllUserPostReview.as_view(), name="show_all"),  # show all
    path('home/', views.ShowAllPost.as_view(), name="all_post"),  # show all post
    path('search/', views.SearchReview.as_view(), name="search_review"),  # search review
    path('user/post_review/', views.UserPostReview.as_view(), name="post_review"),  # post review
    path('user/delete_review/<int:pk>', views.UserDeleteReview.as_view(), name="delete_review"),  # delete review
    path('user/list_review/', views.UserShowListReview.as_view(), name="list_review"),  # show list review
    path('user/update/review/<int:pk>', views.UpdateReviewField.as_view(), name="update_review"),  # update review field
    path('user/update/content/<int:pk>', views.UpdateContentField.as_view(), name="update_review"),  # update content field
    path('user/update/images/<int:pk>', views.UpdateImagesField.as_view(), name="update_review"),  # update images field
    path('user/add/content/', views.AddContentField.as_view(), name="add_content"),  # add content field
    path('user/add/images/', views.AddImageField.as_view(), name="add_images"),  # add images field
    path('user/comment/<int:pk>', views.UserComment.as_view(), name="user_comment"), # user comment
]
