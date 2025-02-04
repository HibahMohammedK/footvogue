
from django.db import models
from django.contrib.auth.models import AbstractUser
from PIL import Image
import secrets
import string
from django.utils import timezone
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now

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
        max_size = (600, 600)
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        img.save(self.image_url.path)


class ProductVariant(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    color = models.ForeignKey('ProductColor', on_delete=models.CASCADE)
    size = models.ForeignKey('ProductSize', on_delete=models.CASCADE)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    stock_quantity = models.IntegerField()
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Add this method
    def get_discounted_price(self):
        from .models import Offer  # Avoid circular import

        original_price = self.price
        best_offer = Offer.objects.filter(
            (models.Q(product=self.product) | models.Q(category=self.product.category)),
            is_active=True,
            start_date__lte=timezone.now(),
            end_date__gte=timezone.now()
        ).order_by('-discount_value').first()  # Get the best available offer

        # Calculate discounted price if an offer exists
        if best_offer:
            if best_offer.discount_type == "fixed":
                discounted_price = max(original_price - best_offer.discount_value, 0)
            elif best_offer.discount_type == "percentage":
                discount_amount = (best_offer.discount_value / 100) * original_price
                discounted_price = max(original_price - discount_amount, 0)
            return discounted_price  # Return discounted price

        return original_price  # Return original price if no offer

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
    

class Address(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="addresses")
    address_line1 = models.CharField(max_length=255)
    address_line2 = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    country = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_default = models.BooleanField(default=False)  # New field to mark default address

    def __str__(self):
        return f"{self.address_line1}, {self.city}, {self.state}, {self.country}"

    class Meta:
        verbose_name_plural = "Addresses"

    def save(self, *args, **kwargs):
        # Ensure only one default address per user
        if self.is_default:
            Address.objects.filter(user=self.user).update(is_default=False)
        super(Address, self).save(*args, **kwargs)


class Coupon(models.Model):
    DISCOUNT_TYPES = [
        ('fixed', 'Fixed Amount'),
        ('percentage', 'Percentage'),
    ]
    
    # Basic Fields
    coupon_code = models.CharField(max_length=50, unique=True)
    discount_type = models.CharField(max_length=10, choices=DISCOUNT_TYPES, default='fixed')
    discount_value = models.DecimalField(max_digits=10, decimal_places=2)  # e.g., 10% or ₹200
    max_discount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  # For capping % discounts
    min_purchase = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    
    # Usage Limits
    usage_limit = models.PositiveIntegerField(default=1)  # Total global uses
    per_user_limit = models.PositiveIntegerField(default=1)  # Uses per user
    used_count = models.PositiveIntegerField(default=0)
    
    # Targeting & Validity
    is_active = models.BooleanField(default=True)
    expiration_date = models.DateTimeField()
    allowed_categories = models.ManyToManyField('Category', blank=True)  # Optional: Limit to shoe categories
    allowed_users = models.ManyToManyField(CustomUser, blank=True)  # Optional: Target specific users
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def is_valid(self, user=None, cart_total=0):
        """Check coupon validity for a user and cart total."""
        now = timezone.now()
        basic_validity = (
            self.is_active and
            self.used_count < self.usage_limit and
            now < self.expiration_date and
            cart_total >= self.min_purchase
        )
        
        # Check user-specific rules
        if user:
            user_usage = UserCouponUsage.objects.filter(coupon=self, user=user).count()
            if user_usage >= self.per_user_limit:
                return False
            if self.allowed_users.exists() and user not in self.allowed_users.all():
                return False
        
        return basic_validity

    def __str__(self):
        return f"{self.coupon_code} ({self.get_discount_type_display()})"
    
    
class UserCouponUsage(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    coupon = models.ForeignKey(Coupon, on_delete=models.CASCADE)
    order = models.ForeignKey('Order', on_delete=models.CASCADE)  # Link to your Order model
    used_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'coupon', 'order')  # Prevent duplicate uses per order

class Order(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Processing', 'Processing'),
        ('Shipped', 'Shipped'),
        ('Cancelled', 'Cancelled'),
        ('Completed', 'Completed'),
    ]

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    order_date = models.DateTimeField(auto_now_add=True)
    shipping_address = models.ForeignKey(Address, on_delete=models.CASCADE)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2)
    discount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    applied_coupon = models.ForeignKey(Coupon, null=True, blank=True, on_delete=models.SET_NULL)

    def get_discount_amount(self):
        return self.discount


    def get_final_amount(self):
        return self.total_amount

    def __str__(self):
        return f"Order #{self.id} - {self.status}"

class OrderItem(models.Model):
    order = models.ForeignKey(Order, related_name="items", on_delete=models.CASCADE)
    product_variant = models.ForeignKey(ProductVariant, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    
    def __str__(self):
        return f"{self.quantity}x {self.product_variant.product.name} for Order #{self.order.id}"
    
class Cart(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product_variant = models.ForeignKey(ProductVariant, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Cart Item - {self.product_variant.product.name} for {self.user.username}"

    def total_price(self):
        return self.product_variant.price * self.quantity

    def save(self, *args, **kwargs):
        # Ensure that quantity is not more than the available stock
        if self.quantity > self.product_variant.stock_quantity:
            self.quantity = self.product_variant.stock_quantity
        super().save(*args, **kwargs)

    @staticmethod
    def get_user_cart(user):
        return Cart.objects.filter(user=user)
    
    def get_discounted_total(self):
        """Calculate total price considering discounts."""
        discounted_price = self.product_variant.get_discounted_price()
        return discounted_price * self.quantity




class Wallet(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name="wallet")
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def credit(self, amount):
        self.balance += amount
        self.save()
    
    def debit(self, amount):
        if self.balance >= amount:
            self.balance -= amount
            self.save()
            return True
        return False

class Offer(models.Model):
    PRODUCT = 'product'
    CATEGORY = 'category'
    REFERRAL = 'referral'
    OFFER_TYPES = [
        (PRODUCT, 'Product Offer'),
        (CATEGORY, 'Category Offer'),
        (REFERRAL, 'Referral Offer')
    ]
    FIXED = 'fixed'
    PERCENTAGE = 'percentage'

    DISCOUNT_TYPE_CHOICES = [
        (FIXED, 'Fixed Discount'),
        (PERCENTAGE, 'Percentage Discount')
    ]

    offer_type = models.CharField(max_length=20, choices=OFFER_TYPES)
    discount_type = models.CharField(max_length=10, choices=DISCOUNT_TYPE_CHOICES, default=PERCENTAGE)  
    product = models.ForeignKey('Product', on_delete=models.CASCADE, null=True, blank=True)
    category = models.ForeignKey('Category', on_delete=models.CASCADE, null=True, blank=True)
    discount_value = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)  
    min_purchase = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)  
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    def is_valid(self):
        return self.start_date <= timezone.now() <= self.end_date

    def save(self, *args, **kwargs):
        """Ensure only one of product or category is set based on offer_type"""
        if self.offer_type == self.PRODUCT:
            self.category = None  # Clear category if it's a product offer
        elif self.offer_type == self.CATEGORY:
            self.product = None  # Clear product if it's a category offer
        else:
            self.product = None
            self.category = None

        super().save(*args, **kwargs)

    def __str__(self):
        if self.offer_type == self.PRODUCT:
            return f"Product Offer - {self.product}"
        elif self.offer_type == self.CATEGORY:
            return f"Category Offer - {self.category}"
        else:
            return "Referral Offer"


class ReferralOffer(models.Model):
    offer = models.OneToOneField(Offer, on_delete=models.CASCADE, related_name="referral_offer")
    reward_amount = models.DecimalField(max_digits=10, decimal_places=2)

class Referral(models.Model):
    referrer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="referrals_made")
    referred_user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name="referral")
    reward_claimed = models.BooleanField(default=False)

    def grant_reward(self):
        if not self.reward_claimed:
            referral_offer = ReferralOffer.objects.first()  # Assuming a single referral offer
            if referral_offer:
                self.referrer.wallet.credit(referral_offer.reward_amount)
                self.reward_claimed = True
                self.save()

class Wishlist(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    product_variant = models.ForeignKey('ProductVariant', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'product_variant')  # Prevent duplicate wishlist entries