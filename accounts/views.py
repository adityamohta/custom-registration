from django.conf import settings
from django.contrib.auth import (
    authenticate,
    get_user_model,
    login,
    logout,
)
from django.contrib.auth.decorators import login_required   # redirect_field_name='my_redirect_field'(arguement)
from django.http import Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone

from .forms import (
    UserRegisterForm,
    UserLoginForm,
    PasswordResetForm,
    ForgotPasswordEmailForm,
)
from .models import UserProfile, ForgotPassword

from . import utils
from datetime import datetime

User = get_user_model()


def home(request):
    return render(request, 'home.html', {})


def register_view(request):
    registration_form = UserRegisterForm()
    if request.method == 'POST':
        if 'signup' in request.POST:
            registration_form = UserRegisterForm(request.POST or None)
            next_var = request.GET.get('next')

            if registration_form.is_valid():
                datas = {}
                datas['username'] = registration_form.cleaned_data.get('username')
                datas['first_name'] = registration_form.cleaned_data.get('firstname')
                datas['last_name'] = registration_form.cleaned_data.get('lastname')
                datas['email'] = registration_form.cleaned_data.get('email')
                datas['password'] = registration_form.cleaned_data.get('password')

                data = utils.generate_activation_key(datas['username'])     # user defined utility function.

                datas['activation_key'] = data

                datas['file_path'] = "accounts/activate/"
                datas['email_path'] = "/ActivationEmail.txt"
                datas['email_subject'] = "Activate Your domainname account."

                registration_form.sendEmail(datas)
                message = '''
                    A Verification email has been sent to your email address.
                    Please click the link in the email to verify your email address.
                    '''
                utils.display_html_message(message, 'success', request)
                registration_form.save(datas)

                request.session['registered'] = True      # For display purposes

                if next_var:
                    return redirect(next_var)
                return redirect('accounts:login')
    else:
        registration_form = UserRegisterForm()

    context = {
        'registration_form': registration_form,
    }
    return render(request, 'register.html', context)


def login_view(request):
    login_form = UserLoginForm()
    next_var = request.GET.get('next')
    if request.method == 'POST':
        if 'login' in request.POST:
            login_form = UserLoginForm(request.POST or None)
            if login_form.is_valid():
                username = login_form.cleaned_data.get('username')
                password = login_form.cleaned_data.get('password')

                # remembers the user for 2 weeks or 1209600 seconds.
                rememberme = login_form.cleaned_data.get('rememberme')
                if rememberme:
                    request.session.set_expiry(1209600)     # set 2 weeks time in user session.
                else:
                    # if remember me was unchecked then session should expire immediately, i.e. 0 seconds
                    request.session.set_expiry(0)
                # remember me ends here.

                user = authenticate(username=username, password=password)
                login(request, user)
                message = 'Logged in.'
                utils.display_html_message(message, 'success', request)
                if next_var:
                    return redirect(next_var)
                return redirect('accounts:login')   # change it to user profile or home page later.
    else:
        login_form = UserLoginForm()

    context = {
        'login_form': login_form,
    }
    return render(request, 'login.html', context)


@login_required
def logout_view(request):
    if request.method == 'POST':
        if 'logout' in request.POST:
            logout(request)
            utils.display_html_message('Logged Out!', 'info', request)
            return redirect('accounts:login')
    return render(request, 'logout.html', {})


def activation(request, key):
    activation_expired = False
    already_active = False
    profile = get_object_or_404(UserProfile, activation_key=key)
    id_user = None
    if not profile.is_active:
        if timezone.now() > profile.key_expires:
            # Display : offer to user to have another activation link
            # (a link in template sending to the view new_activation_link)
            activation_expired = True
            id_user = profile.user.id
        else:   # Activation successful
            profile.is_active = True
            message = 'Your Email is Verified.'
            utils.display_html_message(message, 'success', request)
            profile.save()

    # If user is already active, simply display error message
    else:
        already_active = True
        raise Http404
    return render(request, 'activation.html', locals())     # locals() will pass all these local variables.


def new_activation_link(request, user_id):
    form = UserRegisterForm()
    datas = {}
    user = User.objects.get(id=user_id)
    if user is not None and not user.user_profile.is_active:
        datas['username'] = user.username
        datas['email'] = user.email
        datas['file_path'] = "accounts/new_activate/"
        datas['email_path'] = "/ResendEmail.txt"
        datas['email_subject'] = "activation of your account"

        data = utils.generate_activation_key(datas['username'])     # user defined utility function.
        datas['activation_key'] = data

        profile = UserProfile.objects.get(user=user)
        if profile is not None:
            profile.activation_key = datas['activation_key']
            profile.key_expires = datetime.strftime(
                    timezone.now() + timezone.timedelta(days=2),
                    "%Y-%m-%d %H:%M:%S"
            )
            profile.save()

        form.sendEmail(datas)
        request.session['new_link'] = True      # Display : new link send

    return redirect('accounts:login')


def reset_password_view(request):
    datas = {}
    form = ForgotPasswordEmailForm()
    if request.method == 'POST':
        if 'reset' in request.POST:
            form = ForgotPasswordEmailForm(request.POST or None)
            if form.is_valid():
                datas['email'] = form.cleaned_data.get('email')
                user_qs = User.objects.filter(email=datas['email'])
                if user_qs.count() == 1:
                    user = user_qs.first()
                else:
                    raise Http404
                datas['user'] = user
                datas['username'] = user.username
                datas['file_path'] = "accounts/forgot-password/"
                datas['email_path'] = '/reset_password_link.txt'
                datas['email_subject'] = "Reset your password."
                data = utils.generate_activation_key(datas['username'])
                datas['activation_key'] = data
                form.sendEmail(datas)
                print(datas)
                form.save(datas)
                message = 'Password reset instructions has been sent on your email address.'
                utils.display_html_message(message, 'success', request)
                return redirect('accounts:login')
    else:
        form = ForgotPasswordEmailForm()

    context = {
        'reset_form': form,
    }
    return render(request, 'password_reset_form.html', context)


def reset_password(request, key):
    if request.user.is_authenticated():
        raise Http404
    password_qs = get_object_or_404(ForgotPassword, activation_key=key)
    form = PasswordResetForm()
    if timezone.now() > password_qs.key_expires:
        raise Http404
    if timezone.now() < password_qs.key_expires:
        datas = {}
        if request.method == 'POST':
            if 'reset' in request.POST:
                form = PasswordResetForm(request.POST or None)
                if form.is_valid():
                    datas['password'] = form.cleaned_data.get('new_password')
                    datas['user'] = password_qs.user
                    datas['password_qs'] = password_qs
                    form.save(datas=datas)

                    message = 'Your password is changed now.'
                    utils.display_html_message(message, 'success', request)

                    return redirect('accounts:login')
        else:
            form = PasswordResetForm()
    else:
        raise Http404

    context = {
        'reset_form': form,
    }
    return render(request, 'password_reset_form.html', context)
