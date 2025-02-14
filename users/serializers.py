import re
import random
import uuid
from django.core.mail import send_mail
from django.conf import settings
from twilio.rest import Client
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser
from django.utils import timezone
from datetime import timedelta




User = get_user_model()

# NGO and User Registration
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    ngo_license = serializers.ImageField(required=False)
    first_name = serializers.CharField(max_length=30)
    last_name = serializers.CharField(max_length=30)


    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'contact_number', 'is_ngo', 'ngo_license', 'first_name', 'last_name')

    def validate_email(self, value):
        """Ensure email is unique before registration."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate_contact_number(self, value):
        """Ensure contact number is 10 digits and unique."""
        if not re.match(r"^\d{10}$", value):
            raise serializers.ValidationError("Enter a valid 10-digit phone number.")
        if User.objects.filter(contact_number=value).exists():
            raise serializers.ValidationError("A user with this contact number already exists.")
        return value

    def validate_password(self, value):
        """Ensure password meets complexity requirements."""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Password must contain at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value

    def create(self, validated_data):
        """Create user but keep them inactive until verified."""
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            contact_number=validated_data['contact_number'],
            password=validated_data['password'],
            is_ngo=validated_data.get('is_ngo', False),
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=False  # 🚨 User stays inactive until verified
        )

        # Assign NGO license if provided
        if user.is_ngo and 'ngo_license' in validated_data:
            user.ngo_license = validated_data['ngo_license']

        # ✅ Generate Email Verification Token
        user.email_verification_token = str(uuid.uuid4())

        # Set OTP expiry time to 5 minutes from now
        otp_expiry = timezone.now() + timedelta(minutes=5)
        user.contact_otp_expiry = otp_expiry

        # ✅ Generate OTP for Contact Number
        user.contact_otp = str(random.randint(100000, 999999))

        user.save()

        # ✅ Send Email Verification Link
        self.send_email_verification(user.email, user.email_verification_token)

        # ✅ Send OTP via Twilio
        self.send_sms(user.contact_number, user.contact_otp)

        return user

    def send_email_verification(self, email, token):
        """Send email verification link."""
        verification_link = f"http://localhost:8000/api/users/verify-email/{token}/"
        try:
            send_mail(
                "Verify Your Email",
                f"Click the link to verify your email: {verification_link}",
                "no-reply@giftible.in",
                [email],
                fail_silently=False,
            )
            print(f"✅ Email verification sent to {email}")
        except Exception as e:
            print(f"❌ Failed to send email verification: {str(e)}")

    def send_sms(self, phone_number, otp):
        """Send OTP via Twilio."""
        try:
            # Ensure the phone number is in E.164 format
            if not phone_number.startswith("+"):
                phone_number = "+91" + phone_number  # Assuming Indian numbers

            client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
            message = client.messages.create(
                body=f"Your Giftible verification OTP is {otp}.",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=phone_number
            )
            print(f"✅ OTP sent successfully to {phone_number}: {message.sid}")
        except Exception as e:
            print(f"❌ Failed to send OTP: {str(e)}")

# NGO and User Login
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        user = authenticate(username=username, password=password)
        if not user:
            raise serializers.ValidationError("Invalid username or password")

        if not user.email_verified:
            raise serializers.ValidationError("Email is not verified. Please verify your email before logging in.")

        if not user.contact_verified:
            raise serializers.ValidationError("Contact number is not verified. Please verify your OTP before logging in.")

        tokens = RefreshToken.for_user(user)
        return {
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_ngo": user.is_ngo,
            },
            "access": str(tokens.access_token),
            "refresh": str(tokens),
        }


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, min_length=8)