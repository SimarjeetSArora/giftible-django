from django.urls import path
from .views import RegisterView, LoginView, VerifyEmailView, VerifyContactView,ForgotPasswordView, ResetPasswordView, ProfileUpdateView, UserProfileDeleteView, ApproveNGOView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-email/<uuid:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('verify-contact/', VerifyContactView.as_view(), name='verify-contact'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/<uidb64>/<token>/', ResetPasswordView.as_view(), name='reset-password'),
    path('profile/', ProfileUpdateView.as_view(), name='profile-update'),
    path('profile/delete/', UserProfileDeleteView.as_view(), name='profile-delete'),
    path('approve-ngo/<int:user_id>/', ApproveNGOView.as_view(), name='approve-ngo'),
]
