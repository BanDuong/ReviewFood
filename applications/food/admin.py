from django.contrib import admin
from .models import User


# Register your models here.

@admin.register(User)
class UserInAdmin(admin.ModelAdmin):
    ordering = ('date_joined',)
    list_display = ("id", "username", "first_name", "last_name", "email", "is_staff", "is_admin", "is_superuser",)
    list_filter = ("id", "username", "first_name", "last_name", "email", "is_staff", "is_admin", "is_superuser",)
    search_fields = ("id", "username", "email",)
