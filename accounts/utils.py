from django.conf import settings
from django.contrib import messages
from django.template import Context, Template
import hashlib
import random


def generate_activation_key(username):
    salt = str(random.random())
    if isinstance(salt, str):
        salt = salt.encode('utf8')
    salt = hashlib.sha1(salt).hexdigest()[:5]
    username_salt = username
    if isinstance(username_salt, str):
        username_salt = username_salt.encode('utf8')
    data = str(salt)+str(username_salt)
    if isinstance(data, str):
        data = data.encode('utf-8')

    data = hashlib.sha1(data).hexdigest()
    return data


def send_email(datas):
    link = settings.DOMAIN + datas['file_path'] + datas['activation_key']
    context_var = Context({'activation_link': link, 'username': datas['username']})
    file = open(settings.MEDIA_URL_ROOT + datas['email_path'], 'r')
    t = Template(file.read())
    file.close()
    message = t.render(context_var)

    print(message)
    # uncomment it when smtp mail server is active.
    # send_mail(
    #         subject=datas['email_subject'],
    #         message=message,
    #         html_message=message,
    #         from_email=settings.DOMAIN_NAME,
    #         recipient_list=[datas['email']],
    #         fail_silently=True
    # )


def display_html_message(html_message, message_type, request):
    html_message = settings.MESSAGE % (message_type, html_message)  # type example success.
    messages.success(request, html_message, extra_tags='html_safe')

# funciton to get ip address.
# def get_client_ip(request):
#     ip = request.META.get('HTTP_CF_CONNECTING_IP')
#     if ip is None:
#         ip = request.META.get('REMOTE_ADDR')
#     return ip
