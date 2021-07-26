from django.apps import AppConfig


class FoodConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'applications.food'
    verbose_name = 'Review Food'

    def ready(self):
        import applications.food.signals