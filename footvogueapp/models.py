
from django.db import models
from django.contrib.auth.models import AbstractUser

import random
import string
from django.utils import timezone

class CustomUser(AbstractUser):
    # Additional fields
    name = models.CharField(max_length=255, blank=True, null=True)  # Full name of the user
    phone_number = models.CharField(max_length=15, blank=True, null=True)  # For OTP login
    google_account_id = models.CharField(max_length=255, blank=True, null=True)  # For Google login
    is_verified = models.BooleanField(default=False)  # Whether the user is verified via OTP or email
    is_staff = models.BooleanField(default=False)  # Whether the user is an admin
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the user was created
    updated_at = models.DateTimeField(auto_now=True)  # Timestamp when the user was last updated

    def __str__(self):
        return self.username  # Return the username when the user is printed



class OTP(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)  # Link to CustomUser instead of User
    phone_number = models.CharField(max_length=15)  # Store the phone number
    otp = models.CharField(max_length=6)  # OTP code (6 digits)
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when OTP was created
    is_verified = models.BooleanField(default=False)  # Whether the OTP is verified

    def generate_otp(self):
        """Generate a random 6-digit OTP"""
        self.otp = ''.join(random.choices(string.digits, k=6))  # Generate a random OTP
        self.save()

    def is_expired(self):
        """Check if OTP has expired (valid for 5 minutes)"""
        return timezone.now() - self.created_at > timezone.timedelta(minutes=5)

    def __str__(self):
        return f"OTP for {self.user.username} ({self.phone_number})"
