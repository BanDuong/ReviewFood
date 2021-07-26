from django.db.models.signals import  pre_save,post_save
from django.dispatch import receiver
from .models import Review

# register in apps.py

@receiver(signal=pre_save,sender=Review)
def ResponseCreat(sender,**kwargs):
    print(222)

@receiver(signal=post_save,sender=Review)
def ResponsePost(sender,**kwargs):
    print(111)