from ReviewFood.settings import local
from django.core.mail import send_mail
from django.core.mail.message import EmailMessage


def verify_email(email):
    subject = "Your account need to be verified"
    message = f"Click the link to verify: http://localhost:8000/api/v1/login/"
    from_email = local.EMAIL_HOST_USER
    recipient_list = [email, ]
    send_mail(subject, message, from_email, recipient_list)


def send_content_by_email(to_email, subject="Verify", content="Click here", url=''):
    message = content + '\n' + url
    from_email = local.EMAIL_HOST_USER
    recipient_list = [to_email, ]
    send_mail(subject, message, from_email, recipient_list)

def send_report(from_email, subject, content, file_attach, url=''):
    email = EmailMessage(
        subject,
        content + '\n' + url,
        from_email,
        ["supersirro1@gmail.com",],
        headers={'Reply-To': from_email}
    )
    if file_attach:
        for f in file_attach:
            email.attach(f.name, f.read(), f.content_type)
    email.send()
