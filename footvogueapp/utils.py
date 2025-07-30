import random
import string
from django.core.mail import send_mail
import razorpay
from django.conf import settings
from django.core.cache import cache
from .models import OrderItem, OTP, Product, ProductVariant, ProductImage
from django.db.models import Sum, Prefetch, F, Max, Count
from django.utils import timezone

def generate_and_send_otp(user):
    # Generate a random 6-digit OTP
    otp_code = ''.join(random.choices(string.digits, k=6))
    print(otp_code)

    # Save OTP in the database
    OTP.objects.create(
        user=user,
        email=user.email,
        otp=otp_code
    )

    # Send the OTP via email
    subject = "Verify Your Email - Foot Vogue"
    message = f"Hi {user.username},\n\nYour email verification code is: {otp_code}\n\nThank you for registering with Foot Vogue!"
    from_email = "noreply@footvogue.com"
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)



razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))

def verify_razorpay_payment(order_id, payment_id, signature):
    try:
        params_dict = {
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature,
        }
        razorpay_client.utility.verify_payment_signature(params_dict)
        return True
    except razorpay.errors.SignatureVerificationError:
        return False   
    

def get_sales_analytics(timeframe_days=None, category_id=None):
    """
    Get best selling products and categories with proper image URLs and discounted prices
    """
    cache_key = f'sales_analytics_{timeframe_days}_{category_id}'
    cached_data = cache.get(cache_key)
    
    if cached_data:
        return cached_data

    # Base query for successful orders
    base_query = OrderItem.objects.filter(
        order__payment_status='Paid',
        status='Active'  
    ).select_related('product_variant__product__category')

    # Apply timeframe filter if specified
    if timeframe_days:
        start_date = timezone.now() - timezone.timedelta(days=timeframe_days)
        base_query = base_query.filter(order__created_at__gte=start_date)

    # Apply category filter if specified
    if category_id:
        base_query = base_query.filter(product_variant__product__category_id=category_id)

    # Step 1: Aggregate data at the product level
    top_products_data = (
        base_query.values(
            product_id=F('product_variant__product__id'),
            product_name=F('product_variant__product__name'),
            category_name=F('product_variant__product__category__category_name'),
            category_id=F('product_variant__product__category__id'),
        )
        .annotate(
            total_sold=Sum('quantity'),
            total_revenue=Sum(F('quantity') * F('product_variant__price')),
            variant_price=Max(F('product_variant__price'))  # Get any variant price
        )
        .order_by('-total_sold')
        .distinct()[:10]  # Add distinct to remove duplicates
    )

    top_categories_data = (
        base_query.values(
            category_id=F('product_variant__product__category__id'),
            category_name=F('product_variant__product__category__category_name'),
        )
        .annotate(
            total_sold=Sum('quantity'),
            total_revenue=Sum(F('quantity') * F('product_variant__price')),
            total_products=Count('product_variant__product', distinct=True)
        )
        .order_by('-total_sold')
        .distinct()[:10]
    )


    # Step 2: Fetch image URLs and discounted prices for these products
    product_ids = [p['product_id'] for p in top_products_data]
    
    # Prefetch variants, images, and offers
    products_with_details = Product.objects.filter(
        id__in=product_ids
    ).prefetch_related(
        Prefetch(
            'productvariant_set',
            queryset=ProductVariant.objects.prefetch_related(
                Prefetch(
                    'productimage_set',
                    queryset=ProductImage.objects.order_by('id'),
                    to_attr='images'
                )
            ),
            to_attr='variants'
        )
    )

    # Create mappings for image URLs and discounted prices
    image_url_map = {}
    discounted_price_map = {}

    for product in products_with_details:
        first_variant = product.variants[0] if product.variants else None
        if first_variant:
            first_image = first_variant.images[0] if first_variant.images else None
            image_url_map[product.id] = first_image.image_url.url if first_image else None
            discounted_price_map[product.id] = first_variant.get_discounted_price()
        else:
            image_url_map[product.id] = None
            discounted_price_map[product.id] = None

    # Step 3: Add image URLs and discounted prices to the top products data
    for product in top_products_data:
        product['image_url'] = image_url_map.get(product['product_id'])
        product['discounted_price'] = discounted_price_map.get(product['product_id'])
        product['discount_percentage'] = round(
            ((product['variant_price'] - product['discounted_price']) / product['variant_price'] * 100
        ) if product['discounted_price'] < product['variant_price'] else 0
        )

    result = (list(top_products_data), list(top_categories_data))
    cache.set(cache_key, result, timeout=3600)
    return result