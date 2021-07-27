from ReviewFood.settings import local
from django.core.mail import send_mail

def verify_email(email):
    subject = "Your account need to be verified"
    message = f"Click the link to verify: http://localhost:8000/api/v1/login/"
    from_email = local.EMAIL_HOST_USER
    recipient_list = [email,]
    send_mail(subject,message,from_email,recipient_list)