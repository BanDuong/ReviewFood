from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.mail import send_mail
from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager, Group, Permission
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from .token import generate_access_token


# Create your models here.

class User(AbstractUser):
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
    first_name = models.CharField(_('first name'), max_length=150, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    email = models.EmailField(_('email address'), blank=True, unique=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    is_superuser = models.BooleanField(
        _('superuser status'),
        default=False,
        help_text=_(
            'Designates that this user has all permissions without '
            'explicitly assigning them.'
        ),
    )
    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        help_text=_(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name="user_set",
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('Specific permissions for this user.'),
        related_name="user_set",
        related_query_name="user",
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    is_admin = models.BooleanField(default=False)
    gender = models.CharField(max_length=35, blank=True, null=True)
    # phonenumber = models.DecimalField(decimal_places=,verbose_name='phonenumber', blank=True, null=True)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        db_table = 'tbl_user'
        verbose_name = _('user')
        verbose_name_plural = _('user')

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)

    # def get_token(self):
    #     return generate_access_token(self)


class TimeStamp(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="create")
    updated_at = models.DateTimeField(auto_now_add=True, verbose_name="update")

    class Meta:
        abstract = True


class Review(TimeStamp):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="review", null=True, blank=True)
    title = models.CharField(max_length=255, blank=True, null=True, verbose_name="title")
    image_title = models.ImageField(verbose_name="image_title", upload_to="media/", blank=True, null=True)
    status = models.BooleanField(default=False)

    def __str__(self):
        return self.title

    class Meta:
        db_table = "tb_review"
        verbose_name_plural = "review"


class Content(TimeStamp):
    title = models.ForeignKey(Review, on_delete=models.CASCADE, related_name="content", null=True, blank=True)
    heading = models.CharField(max_length=255, blank=True, null=True, verbose_name="heading")
    content = models.TextField(blank=True, null=True, verbose_name="content")

    def __str__(self):
        return self.heading

    class Meta:
        db_table = "tb_content"
        verbose_name_plural = "content"


class Image(TimeStamp):
    content = models.ForeignKey(Content, on_delete=models.CASCADE, related_name="image", null=True, blank=True)
    images = models.ImageField(verbose_name="image", upload_to="media/", blank=True, null=True)

    def __str__(self):
        return self.images.name

    class Meta:
        db_table = "tb_image"
        verbose_name_plural = "image"
