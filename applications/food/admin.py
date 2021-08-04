from django.contrib import admin
from .models import *


# Register your models here.

@admin.register(User)
class UserInAdmin(admin.ModelAdmin):
    ordering = ('date_joined',)
    list_display = ("id", "username", "first_name", "last_name", "email", "is_staff", "is_admin", "is_superuser",)
    list_filter = ("id", "username", "first_name", "last_name", "email", "is_staff", "is_admin", "is_superuser",)
    search_fields = ("id", "username", "email",)


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    ordering = ('created_at',)
    list_filter = ('id', 'title', 'user')
    list_display = ('id', 'user', 'title', 'image_title', 'created_at', 'updated_at',)
    search_fields = ('id', 'title', 'user')


@admin.register(Content)
class ContentAdmin(admin.ModelAdmin):
    ordering = ('created_at',)
    list_filter = ('id', 'heading',)
    list_display = ('id', 'heading','created_at', 'updated_at',)
    search_fields = ('id', 'heading', 'title', 'user')


@admin.register(Image)
class Image(admin.ModelAdmin):
    ordering = ('created_at',)
    list_filter = ('id', 'images',)
    list_display = ('id', 'images', 'created_at', 'updated_at',)
    search_fields = ('id', 'content', 'images', 'user')
