from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from .serializers import RegisterSerializer
from .models import CustomUser
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.core.mail import send_mail
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from .serializers import PasswordResetSerializer



class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        """
        Handles user and NGO registration.
        If is_ngo=True, the NGO license image is required.
        """
        data = request.data.copy()
        is_ngo = data.get('is_ngo', 'false')
        is_ngo = str(is_ngo).lower() == 'true'  # Convert to Boolean

        if is_ngo and 'ngo_license' not in request.FILES:
            return Response(
                {"error": "NGO registration requires an NGO license image."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        response_message = "NGO registered successfully!" if user.is_ngo else "User registered successfully!"

        return Response(
            {
                "message": response_message,
                "user": {
                    "username": user.username,
                    "email": user.email,
                    "contact_number": user.contact_number,
                    "is_ngo": user.is_ngo,
                    "ngo_license": user.ngo_license.url if user.is_ngo and user.ngo_license else None
                }
            },
            status=status.HTTP_201_CREATED
        )

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class VerifyEmailView(generics.GenericAPIView):
    def get(self, request, token):
        user = get_object_or_404(CustomUser, email_verification_token=token)
        user.email_verified = True
        user.save()
        return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)

class VerifyContactView(generics.GenericAPIView):
    def post(self, request):
        contact_number = request.data.get("contact_number")
        otp = request.data.get("otp")

        user = get_object_or_404(CustomUser, contact_number=contact_number)

        # Check if OTP has expired (assuming 10 minutes expiry time)
        if user.is_otp_expired():
            return Response({"error": "OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)

        # Verify OTP
        if user.contact_otp == otp:
            user.contact_verified = True
            user.contact_otp = None  # Remove OTP after verification
            user.otp_expiry = None   # Clear OTP expiry time
        
            # Activate the user after successful OTP verification
            user.is_active = True
        
            user.save()
            return Response({"message": "Contact verified successfully! User is now active."}, status=status.HTTP_200_OK)
        
        return Response({"error": "Invalid OTP!"}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(APIView):
    def post(self, request, *args, **kwargs):
        """Handles forgot password functionality"""
        email = request.data.get("email")
        try:
            user = get_user_model().objects.get(email=email)
            
            # Encode user.pk properly without decoding
            uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))

            # Generate the password reset token
            token = default_token_generator.make_token(user)

            # Create the reset link
            reset_link = f"http://localhost:8000/api/users/reset-password/{uid}/{token}/"
            
            # Send reset link via email
            send_mail(
                "Password Reset Request",
                f"Click the link to reset your password: {reset_link}",
                "no-reply@giftible.in",
                [email],
                fail_silently=False,
            )

            return Response({"message": "Password reset link sent to your email."}, status=status.HTTP_200_OK)
        
        except get_user_model().DoesNotExist:
            return Response({"error": "Email not found."}, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    def post(self, request, uidb64, token):
        """Handles password reset functionality"""
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            return Response({"error": "Invalid reset link."}, status=status.HTTP_400_BAD_REQUEST)
        
        if not default_token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        # Set new password
        new_password = request.data.get("new_password")
        user.set_password(new_password)
        user.save()

        return Response({"message": "Password reset successful!"}, status=status.HTTP_200_OK)