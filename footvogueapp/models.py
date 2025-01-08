
from django.db import models
from django.contrib.auth.models import AbstractUser
from PIL import Image
import secrets
import string
from django.utils import timezone
from django.conf import settings

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
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    is_verified = models.BooleanField(default=False)

    def generate_otp(self):
        """Generate a secure random 6-digit OTP"""
        self.otp = ''.join(secrets.choice(string.digits) for _ in range(6))
        self.save()

    def is_expired(self):
        """Check if OTP has expired (valid for 5 minutes)"""
        return timezone.now() - self.created_at > timezone.timedelta(minutes=5)

    def __str__(self):
        return f"OTP for {self.user.username if self.user else self.email} - {self.otp}"

    class Meta:
        unique_together = ('email', 'otp')
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['otp']),
        ]


#### admin models ###

class Category(models.Model):
    category_name = models.CharField(max_length=255, unique=True)
    parent_category = models.ForeignKey(
        'self', on_delete=models.SET_NULL, null=True, blank=True, related_name='subcategories'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        self.category_name = self.category_name.lower()  # Convert to lowercase before saving
        super().save(*args, **kwargs)

class Product(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    category = models.ForeignKey(Category, on_delete=models.CASCADE, default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return self.name

class ProductImage(models.Model):
    variant = models.ForeignKey('ProductVariant', on_delete=models.CASCADE)
    image_url = models.ImageField(upload_to='product_images/')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        img = Image.open(self.image_url.path)
        if img.height > 600 or img.width > 600:
            img = img.resize((600, 600), Image.Resampling.LANCZOS) 
            img.save(self.image_url.path)


class ProductVariant(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    color = models.ForeignKey('ProductColor', on_delete=models.CASCADE)
    size = models.ForeignKey('ProductSize', on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock_quantity = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class ProductColor(models.Model):
    color_name = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class ProductSize(models.Model):
    size_name = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Review(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='reviews')
    review_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'Review by {self.user} on {self.product}'

class Rating(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='ratings')
    rating = models.PositiveIntegerField()  # Ensure ratings are positive integers (e.g., 1-5)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'Rating {self.rating} by {self.user} for {self.product}'