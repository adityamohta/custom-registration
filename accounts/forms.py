from django import forms
from django.conf import settings
from django.contrib.auth import (
    authenticate,
    get_user_model,
)

from django.utils import timezone

from captcha.fields import ReCaptchaField

from .models import UserProfile, ForgotPassword
from . import utils
import re

User = get_user_model()


class UserRegisterForm(forms.ModelForm):
    username = forms.CharField(label='Username')
    email = forms.EmailField(label='Email')
    email2 = forms.EmailField(label='Confirm Email')
    password = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput)
    firstname = forms.CharField(label='First Name')
    lastname = forms.CharField(label='Last Name')
    captcha = ReCaptchaField(attrs={'theme': 'clean'})

    # To allow for runtime specification of keys and SSL usage
    # you can optionally pass private_key, public_key or use_ssl parameters to the constructor,
    # captcha = ReCaptchaField(
    #                   public_key='76wtgdfsjhsydt7r5FFGFhgsdfytd656sad75fgh',
    #                   private_key='98dfg6df7g56df6gdfgdfg65JHJH656565GFGFGs',
    #                   use_ssl=True)

    class Meta:
        model = User
        fields = [
            'username',
            'firstname',
            'lastname',
            'email',
            'email2',
            'password',
            'password2',
            'captcha',
        ]

    def clean_username(self):  # this will give error on the field.
        username = self.cleaned_data.get('username')
        # Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.
        if len(username) > 30:
            raise forms.ValidationError("Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.")

        if not re.match("^[A-Za-z0-9@.+_-]*$", username):
            raise forms.ValidationError("Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.")

        return username

    def clean_firstname(self):
        firstname = self.cleaned_data.get('firstname')
        length = len(firstname)
        if 28 < length or length < 1:
            raise forms.ValidationError("Length of Name must be in range of 1 to 28 characters")

        if not re.match("^[A-Za-z]*$", firstname):
            raise forms.ValidationError("First name should only contain letters.")

        return firstname

    def clean_lastname(self):
        lastname = self.cleaned_data.get('lastname')
        if not re.match("^[A-Za-z]*$", lastname):
            raise forms.ValidationError("Last name should only contain letters.")
        return lastname

    def clean_password2(self):
        password = self.cleaned_data.get('password')
        password2 = self.cleaned_data.get('password2')
        if password != password2:
            raise forms.ValidationError("Passwords must match")
        if not 8 < len(str(password)) < 30:
            raise forms.ValidationError("Password's length must be in between 8 to 30 characters.")
        return password

    def clean_email2(self):
        # print(self.cleaned_data)
        email = self.cleaned_data.get('email')
        email2 = self.cleaned_data.get('email2')
        if email != email2:
            raise forms.ValidationError("Emails must match")
        email_qs = User.objects.filter(email=email)
        if email_qs.exists():
            raise forms.ValidationError("This email has already been registered.")
        return email

    def save(self, datas):
        new_user = User.objects.create_user(
                username=datas['username'],
                email=datas['email'],
                password=datas['password'],
                first_name=datas['first_name'],
                last_name=datas['last_name'],
        )
        new_user.is_active = True
        new_user.save()
        user_profile = UserProfile()
        user_profile.user = new_user
        user_profile.activation_key = datas['activation_key']
        user_profile.is_active = False  # Will be true if email is verified.
        user_profile.save()
        return new_user

    def sendEmail(self, datas):
        utils.send_email(datas)     # user defined utility function.


class UserLoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)
    captcha = ReCaptchaField(attrs={'theme': 'clean'})
    rememberme = forms.BooleanField(label="Remember Me", required=False)

    def clean(self, *args, **kwargs):  # this will give errors on the whole form.
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise forms.ValidationError("this user doesn't exists")

            if not user.check_password(password):
                raise forms.ValidationError("Incorrect Password")

            if not user.is_active:
                raise forms.ValidationError("Please Confirm Your Email Address.")

        return super(UserLoginForm, self).clean(*args, **kwargs)


class ForgotPasswordEmailForm(forms.ModelForm):
    email = forms.EmailField(label='Your Email')

    class Meta:
        model = User
        fields = [
            'email',
        ]

    def clean_email(self):
        email = self.cleaned_data.get('email')
        email_qs = User.objects.filter(email=email)
        if not email_qs.exists():
            raise forms.ValidationError('User with this email address doesn\'t exist.')
        return email

    def sendEmail(self, datas):
        utils.send_email(datas)

    def save(self, datas):
        try:
            datas['user'].forgot_password.delete()
            forgot_pass_obj = ForgotPassword()
        except:
            forgot_pass_obj = ForgotPassword()
        forgot_pass_obj.user = datas['user']
        forgot_pass_obj.activation_key = datas['activation_key']
        forgot_pass_obj.save()


class PasswordResetForm(forms.ModelForm):

    new_password = forms.CharField(label='New Password', widget=forms.PasswordInput)
    new_password2 = forms.CharField(label='Confirm New Password', widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = [
            'new_password',
            'new_password2',
        ]

    def clean_new_password2(self):
        new_password = self.cleaned_data.get('new_password')
        new_password2 = self.cleaned_data.get('new_password2')
        if new_password != new_password2:
            raise forms.ValidationError("Passwords must match")
        if not 8 < len(str(new_password)) < 30:
            raise forms.ValidationError("Password's length must be in between 8 to 30 characters.")
        return new_password

    def save(self, commit=True, datas=None):
        user = datas['user']
        user.set_password(datas['password'])
        password_qs = datas['password_qs']
        password_qs.key_expires -= timezone.timedelta(minutes=20)
        password_qs.save()
        user.save()
