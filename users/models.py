from django.contrib.auth.models import AbstractUser
from django.db import models
import random
import string
import uuid
from datetime import timedelta
from django.utils import timezone


# Function to validate NGO License
def validate_ngo_license(value):
    allowed_types = ["application/pdf", "image/png", "image/jpeg"]
    max_size = 5 * 1024 * 1024  # 5MB

    if value.content_type not in allowed_types:
        raise ValidationError("Invalid file type. Allowed: PDF, PNG, JPG, JPEG.")

    if value.size > max_size:
        raise ValidationError("File too large. Maximum size allowed is 5MB.")

    return value
# Function to define file path for the NGO license upload
def ngo_license_upload_path(instance, filename):
    return f'ngo_licenses/{instance.username}/{filename}'  # ✅ Save inside username folder


def ngo_logo_upload_path(instance, filename):
    return f'ngo_logos/{instance.username}/{uuid.uuid4().hex}_{filename}'

# Function to generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)  # Enforce unique emails
    contact_number = models.CharField(max_length=15, unique=True)

    is_ngo = models.BooleanField(default=False)
    ngo_license = models.FileField(
        upload_to=ngo_license_upload_path,
        null=True,
        blank=True,
        validators=[validate_ngo_license]
    )  # ✅ Add validation function  # ✅ Updated
    ngo_logo = models.ImageField(upload_to=ngo_logo_upload_path, null=True, blank=True)  # NGO logo field

    email_verified = models.BooleanField(default=False)
    contact_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)  # User is inactive until verified
    is_approved = models.BooleanField(default=False)  # Admin approval required for NGOs

    email_verification_token = models.UUIDField(default=uuid.uuid4, unique=True)
    contact_otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)  # OTP expiry time

    def __str__(self):
        return self.username

    # Method to check if OTP has expired (assuming 10 minutes expiry)
    def is_otp_expired(self):
        if self.otp_expiry:
            return timezone.now() > self.otp_expiry
        return False

    # Method to generate OTP and set expiry time
    def generate_and_set_otp(self):
        otp = generate_otp()  # Generate OTP
        self.contact_otp = otp
        self.otp_expiry = timezone.now() + timedelta(minutes=10)  # Set expiry to 10 minutes from now
        self.save()
        return otp
