from django.urls import path
from .views import RegisterView
from .views import LoginView
from .views import VerifyEmailView, VerifyContactView
from .views import ForgotPasswordView, ResetPasswordView


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-email/<uuid:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('verify-contact/', VerifyContactView.as_view(), name='verify-contact'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordView.as_view(), name='reset-password'),
]
