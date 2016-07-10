from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.db.models import Q

from accounts.models import UserProfile
from .. import utils

import re

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    username = serializers.CharField(label='Username')
    email = serializers.EmailField(label='Email')
    email2 = serializers.EmailField(label='Confirm Email')
    password = serializers.CharField()
    password2 = serializers.CharField(label='Confirm Password')
    first_name = serializers.CharField(label='First Name')
    last_name = serializers.CharField(label='Last Name')

    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'email2',
            'password',
            'password2',
            'first_name',
            'last_name',
        ]

        extra_kwargs = {
            'password': {"write_only": True},
            'password2': {"write_only": True},
        }

    # def validate(self, data):
    #     email = data['email']
    #     user_qs = User.objects.filter(email=email)
    #     if user_qs.exists():
    #         raise serializers.ValidationError('This User has already registered.')
    #     return data

    def validate_username(self, value):
        username = value
        user_qs = User.objects.filter(username=username)
        if user_qs.exists():
            raise serializers.ValidationError('A User with this username already exist.')
        if len(username) > 30:
            raise serializers.ValidationError("Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.")
        if not re.match("^[A-Za-z0-9@.+_-]*$", username):
            raise serializers.ValidationError("Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only.")

        return value

    def validate_first_name(self, value):
        first_name = value
        length = len(first_name)

        if 28 < length or length < 1:
            raise serializers.ValidationError("Length of Name must be in range of 1 to 28 characters")
        if not re.match("^[A-Za-z]*$", first_name):
            raise serializers.ValidationError("First name should only contain letters.")

        return first_name

    def validate_last_name(self, value):
        last_name = value

        if not re.match("^[A-Za-z]*$", last_name):
            raise serializers.ValidationError("Last name should only contain letters.")

        return last_name

    def validate_email2(self, value):
        data = self.get_initial()
        email1 = data.get('email')
        email2 = value

        if email1 != email2:
            raise serializers.ValidationError('Emails Must Match.')
        return value

    def validate_password2(self, value):
        data = self.get_initial()
        password1 = data.get('password')
        password2 = value

        if password1 != password2:
            raise serializers.ValidationError('Password Must Match.')
        if not 8 < len(str(password1)) < 30:
            raise serializers.ValidationError("Password's length must be in between 8 to 30 characters.")
        return value

    def create(self, validated_data):
        datas = {}
        datas['username'] = validated_data['username']
        datas['email'] = validated_data['email']
        datas['password'] = validated_data['password']
        datas['first_name'] = validated_data['first_name']
        datas['last_name'] = validated_data['last_name']
        datas['password'] = validated_data['password']

        data = utils.generate_activation_key(datas['username'])     # user defined utility function.
        datas['activation_key'] = data
        datas['file_path'] = "accounts/activate/"
        datas['email_path'] = "/ActivationEmail.txt"
        datas['email_subject'] = "Activate Your domainname account."

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
        utils.send_email(datas)
        # message = '''
        #             A Verification email has been sent to your email address.
        #             Please click the link in the email to verify your email address.
        #             '''
        # utils.display_html_message(message, 'success', request)
        return validated_data


class UserLoginSerializer(serializers.ModelSerializer):
    token = serializers.CharField(allow_blank=True, read_only=True)
    username = serializers.CharField(label='Username', allow_blank=True, required=False)
    email = serializers.EmailField(label='Email Address', allow_blank=True, required=False)

    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'password',
            'token',
        ]

        extra_kwargs = {
            "password": {"write_only": True}
        }

    def validate(self, data):
        user = None
        email = data.get('email', None)
        username = data.get('username', None)
        password = data["password"]
        if not email and not username:
            raise serializers.ValidationError("A Username or the Email is required to login.")
        user = User.objects.filter(
                Q(email=email) |
                Q(username=username)
        ).distinct()
        # if there is no email address associated to user objects.
        user = user.exclude(email__isnull=True).exclude(email__iexact='')

        if user.exists() and user.count() == 1:
            user_obj = user.first()
        else:
            raise serializers.ValidationError("This Username/email is not valid.")

        if user_obj:
            if not user_obj.check_password(password):
                raise serializers.ValidationError('Incorrect Credentials please try again.')

        # This token will be used later to confirm if the user is logged in or not.
        data['token'] = "Some Random Token"

        return data



