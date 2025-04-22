import logging
import json
import datetime
import razorpay
import pandas as pd
from dateutil import parser
from datetime import timezone as dt_timezone

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.template.loader import render_to_string
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.core.mail import EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import (
    authenticate, 
    login as auth_login, 
    logout, 
    update_session_auth_hash
)
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.views import PasswordResetView
from django.contrib.auth.password_validation import validate_password
from django.contrib import messages
from django.contrib.messages import success, error
from django.db import transaction
from django.db.models import Avg, Sum, Count, Q, Min, Max
from django.db.models.functions import TruncDay
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_GET

from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, 
    Paragraph, 
    Spacer, 
    Table, 
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet

from .models import *  
from .forms import ReviewForm, RatingForm, CategoryForm, UserUpdateForm, AddressForm
from .utils import (
    generate_and_send_otp, 
    get_sales_analytics, 
    verify_razorpay_payment
)


@never_cache
def home(request):
    # Fetch all categories for the navbar
    categories = Category.objects.all()

    # Get the selected category from the request
    selected_category = request.GET.get('category')

    # Fetch top-selling products (category-wise if a category is selected)
    top_products, top_categories = get_sales_analytics(category_id=selected_category)

    # Fetch products for the main product listing
    products = Product.objects.prefetch_related(
        'productvariant_set__productimage_set'
    ).filter(is_deleted=False)

    # Fetch cart items for the logged-in user
    cart_items = []
    total_price = 0

    if request.user.is_authenticated:
        cart_items = Cart.objects.filter(user=request.user)
        total_price = sum(item.quantity * item.product_variant.price for item in cart_items)

        for item in cart_items:
            image = ProductImage.objects.filter(variant=item.product_variant).first()
            item.image_url = image.image_url.url if image else None

    context = {
        'products': products,
        'categories': categories,
        'rating_range': range(1, 6),
        'cart_items': cart_items,
        'total_price': total_price,
        'top_products': top_products,
        'top_categories': top_categories,
        'selected_category': selected_category,
    }

    return render(request, 'user/home.html', context)


def get_top_products(request):
    selected_category = request.GET.get('category')

    # Fetch top-selling products (same logic as the home view)
    top_products, _ = get_sales_analytics(category_id=selected_category)

    # Render the products HTML
    products_html = render_to_string('user/product_list.html', {'top_products': top_products})

    return JsonResponse({'products_html': products_html})


def search_results(request):
    category_id = request.GET.get("category", "0")
    query = request.GET.get("query", "")

    # Filter products based on the search query and category
    if category_id == "0":
        products = Product.objects.filter(name__icontains=query)
    else:
        products = Product.objects.filter(category_id=category_id, name__icontains=query)

    product_data = []
    for product in products:
        variant = product.productvariant_set.first()  # Get the first variant
        price = float(variant.price) if variant else "Price not available"

        product_image = None
        if variant:
            first_image = variant.productimage_set.first()
            product_image = first_image.image_url.url if first_image else "/static/images/no-image-available.png"

        product_data.append({
            "id": product.id,
            "name": product.name,
            "category": product.category.category_name,
            "price": price,
            "image_url": product_image,
        })

    return JsonResponse({"results": product_data})


@never_cache
def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username").strip()
        email = request.POST.get("email").strip()
        password = request.POST.get("password").strip()
        confirm_password = request.POST.get("confirm_password").strip()
        phone_number = request.POST.get("phone_number").strip()
        referral_code = request.POST.get("referral_code", "").strip()  # Get referral code (if provided)

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("register")

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("register")

        # Validate the password using Django's built-in validators
        try:
            validate_password(password)
        except ValidationError as e:
            for error in e.messages:
                messages.error(request, error)
            return redirect("register")

        # Create the user but set `is_verified=False`
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            phone_number=phone_number,
            is_verified=False
        )
        user.save()

        # ✅ Handle Referral System
        if referral_code:
            try:
                referrer = CustomUser.objects.get(referral_code=referral_code)
                Referral.objects.create(referrer=referrer, referred_user=user)
            except CustomUser.DoesNotExist:
                messages.warning(request, "Invalid referral code.")  # Optional: Inform the user

        # Generate and send the OTP
        generate_and_send_otp(user)

        # Redirect to email verification page
        messages.success(request, "Registration successful! Verify your email to activate your account.")
        return redirect("email_verification")  # Define this route

    return render(request, "user/register.html")


def resend_otp(request):
    user_id = request.session.get('unverified_user_id')  # Get the unverified user's ID from the session
    if user_id:
        user = CustomUser.objects.filter(id=user_id).first()
        if user:
            generate_and_send_otp(user)
            messages.success(request, 'OTP has been resent to your email.')
            return redirect('email_verification')

    messages.error(request, 'No user found to resend OTP. Please log in again.')
    return redirect('login')


@never_cache
def email_verification_view(request):
    if request.method == "POST":
        otp_code = request.POST.get("otp", "").strip()

        try:
            # Look for the OTP related to the user's email
            otp = OTP.objects.get(otp=otp_code)

            # Check if the OTP is expired
            if otp.is_expired():
                messages.error(request, "OTP has expired. Please request a new one.")
                return redirect("email_verification")

            # Mark the OTP as verified
            otp.is_verified = True
            otp.save()

            # Mark the associated user as verified
            user = otp.user
            user.is_verified = True
            user.save()

            # Log the user in
            auth_login(request, user)

            # Display a success message and redirect to home
            messages.success(request, "Email verified successfully! Welcome to the site.")
            return redirect("home")  # Redirect to the home page after verification

        except OTP.DoesNotExist:
            messages.error(request, "Invalid OTP.")
            return redirect("email_verification")

    return render(request, "user/email_verification.html")


def logout_view(request):
    logout(request)
    return redirect('home')


@never_cache
def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        login_identifier = request.POST.get('login_identifier')
        password = request.POST.get('password')

        user_instance = None
        if '@' in login_identifier and '.' in login_identifier:
            user_instance = CustomUser.objects.filter(email=login_identifier).first()
        else:
            user_instance = CustomUser.objects.filter(username=login_identifier).first()

        if user_instance:
            if not user_instance.is_staff and not user_instance.is_verified:
                # Store the user's ID in the session
                request.session['unverified_user_id'] = user_instance.id

                # Generate and send OTP
                generate_and_send_otp(user_instance)

                messages.info(request, 'Your email is not verified. We have sent you an OTP. Please verify your email.')
                return redirect('email_verification')

            # Authenticate and log in verified users
            user = authenticate(request, username=user_instance.username, password=password)
            if user:
                auth_login(request, user)
                if user.is_staff:
                    return redirect('admin_dash')
                return redirect('home')
            else:
                messages.error(request, 'Invalid credentials.')
        else:
            messages.error(request, 'No user found with the provided identifier.')

    return render(request, 'login.html')


class CustomPasswordResetView(PasswordResetView):
    def send_mail(self, subject_template_name, email_template_name, context, from_email, to_email, html_email_template_name=None):
        request = self.request
        context["domain"] = get_current_site(request).domain  # Dynamically fetch site domain
        context["protocol"] = "https" if request.is_secure() else "http"  # Ensure correct protocol
        
        subject = render_to_string(subject_template_name, context).strip()
        message_txt = render_to_string(email_template_name, context)
        message_html = render_to_string(html_email_template_name, context) if html_email_template_name else None
        
        
        email = EmailMultiAlternatives(subject, message_txt, from_email, [to_email])
        if message_html:
            email.attach_alternative(message_html, "text/html")
        email.send()


### admin view ###

@never_cache
@login_required
def admin_dash(request):
    if not request.user.is_superuser:
        return redirect('login')  # Ensure only admin can access

    # Render the admin dashboard template
    return render(request, 'admin/admin_dash.html')


@login_required
def user_management(request):
    if not request.user.is_superuser:
        return redirect('login')  # Ensure only admin can access

    # Get the search query (if any)
    query = request.GET.get('q', '')

    if query:
        # Filter users by username or email
        users = CustomUser.objects.filter(
            username__icontains=query
        ) | CustomUser.objects.filter(
            email__icontains=query
        )
    else:
        # If no query, show all users
        users = CustomUser.objects.all()

    return render(request, 'admin/user_management.html', {'users': users, 'query': query})


@login_required
def block_user(request, user_id):
    if not request.user.is_superuser:
        return redirect('login')  # Ensure only superusers can access

    user = get_object_or_404(CustomUser, id=user_id)
    
    # Prevent the admin from blocking themselves
    if user == request.user:
        messages.error(request, "You cannot block yourself.")
        return redirect('user_management')
    
    user.is_active = False  # Block the user
    user.save()
    messages.success(request, f"User {user.username} has been blocked.")
    return redirect('user_management')


@login_required
def unblock_user(request, user_id):
    if not request.user.is_superuser:
        return redirect('login')  # Ensure only admin can access

    user = get_object_or_404(CustomUser, id=user_id)
    user.is_active = True  # Unblock the user
    user.save()
    messages.success(request, f"User {user.username} has been unblocked.")
    return redirect('user_management')


def index(request):
    return render(request,'admin/index.html')


def category_list(request):
    categories = Category.objects.filter(is_deleted=False)
    return render(request, 'admin/categories/category_list.html', {'categories': categories})


def add_category(request):
    if request.method == 'POST':
        category_name = request.POST.get('category_name').strip()  # Remove extra spaces
        parent_category_id = request.POST.get('parent_category')  # Get the parent category ID

        # Check if a category with the same name already exists (case-insensitive)
        existing_category = Category.objects.filter(Q(category_name__iexact=category_name)).first()

        if existing_category:
            if existing_category.is_deleted:
                # If the category exists but is soft-deleted, restore it
                existing_category.is_deleted = False
                existing_category.save()
                messages.success(request, f"Category '{category_name}' restored successfully!")
            else:
                # If the category already exists and is not deleted, prevent duplicate entry
                messages.error(request, f"Category '{category_name}' already exists!")
                return render(request, 'admin/categories/add_category.html', {'form': CategoryForm()})
        else:
            # If no such category exists, create a new one
            form = CategoryForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, f"Category '{category_name}' added successfully!")
            else:
                messages.error(request, "Error adding category. Please try again.")
                return render(request, 'admin/categories/add_category.html', {'form': form})

        return redirect('category_list')

    else:
        form = CategoryForm()
    return render(request, 'admin/categories/add_category.html', {'form': form})


def edit_category(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    if request.method == 'POST':
        form = CategoryForm(request.POST, instance=category)
        if form.is_valid():
            form.save()
            messages.success(request, "Category updated successfully!")
            return redirect('category_list')
    else:
        form = CategoryForm(instance=category)
    return render(request, 'admin/categories/edit_category.html', {'form': form})


def delete_category(request, category_id):
    category = Category.objects.get(id=category_id)
    category.is_deleted = True  # Soft delete the category
    category.save()
    messages.success(request, "Category deleted successfully!")
    return redirect('category_list')  # Redirect back to the category list


# products

logger = logging.getLogger(__name__)

def view_products(request):
    products = Product.objects.prefetch_related(
        'productvariant_set__productimage_set'
    ).filter(is_deleted=False)

    return render(request, 'admin/products/view_products.html', {'products': products})


def add_product(request):
    if request.method == 'POST':
        # Create Product
        product = Product.objects.create(
            name=request.POST['name'],
            description=request.POST['description'],
            category_id=request.POST['category']
        )

        # Process Colors
        colors = {}
        i = 0
        while f'color_{i}_name' in request.POST:
            color = ProductColor.objects.create(
                color_name=request.POST[f'color_{i}_name'],
            )
            # Save images for this color
            images = request.FILES.getlist(f'color_{i}_images')
            colors[i] = (color, images)
            i += 1

        # Process Sizes
        sizes = {}
        j = 0
        while f'size_{j}' in request.POST:
            size, _ = ProductSize.objects.get_or_create(
                size_name=request.POST[f'size_{j}']
            )
            sizes[j] = size
            j += 1

        # Process Variants
        for color_idx, (color, images) in colors.items():
            for size_idx, size in sizes.items():
                if f'variant_{color_idx}_{size_idx}_price' in request.POST:
                    # Create Variant
                    variant = ProductVariant.objects.create(
                        product=product,
                        color=color,
                        size=size,
                        price=request.POST[f'variant_{color_idx}_{size_idx}_price'],
                        stock_quantity=request.POST[f'variant_{color_idx}_{size_idx}_stock']
                    )
                    
                    # Save Images for this variant
                    for image in images:
                        ProductImage.objects.create(
                            variant=variant,
                            image_url=image
                        )

        messages.success(request, "Product and variants added successfully!")
        return redirect("add_product")

    categories = Category.objects.all().exclude(is_deleted=True)
    return render(request, "admin/products/add_products.html", {"categories": categories})


def edit_product(request, pk):
    # Fetch the product, its variants, and related categories
    product = get_object_or_404(Product, id=pk)
    variants = ProductVariant.objects.filter(product=product)
    categories = Category.objects.all()  # For the category dropdown

    if request.method == 'POST':
        # Update the main product fields
        product.name = request.POST.get('name', product.name)
        product.description = request.POST.get('description', product.description)
        category_id = request.POST.get('category', product.category_id)
        product.category = get_object_or_404(Category, id=category_id)  # Ensure valid category
        product.save()

        # Update the product variants
        for variant in variants:
            # Update price and stock_quantity
            price = request.POST.get(f'variant_{variant.id}_price')
            stock = request.POST.get(f'variant_{variant.id}_stock')

            if price is not None:
                variant.price = float(price)
            if stock is not None:
                variant.stock_quantity = int(stock)

            # Update color (expects a color ID from the form)
            color_id = request.POST.get(f'variant_{variant.id}_color')
            if color_id:
                variant.color = get_object_or_404(ProductColor, id=color_id)

            # Update size (expects a size ID from the form)
            size_id = request.POST.get(f'variant_{variant.id}_size')
            if size_id:
                variant.size = get_object_or_404(ProductSize, id=size_id)

            variant.save()

        # Redirect after successful update
        return redirect('view_products')  # Adjust URL as needed

    # Fetch colors and sizes for the form
    colors = ProductColor.objects.all()
    sizes = ProductSize.objects.all()

    return render(request, 'admin/products/edit_product.html', {
        'product': product,
        'variants': variants,
        'categories': categories,
        'colors': colors,
        'sizes': sizes,
    })


def delete_product(request, pk):
    product = get_object_or_404(Product, pk=pk)

    # Soft delete the product
    product.is_deleted = True
    product.save()

    # Soft delete associated variants
    product.productvariant_set.update(is_deleted=True)

    # Add a success message
    messages.success(request, "Product and its variants were successfully deleted!")

    return redirect('view_products')


#order
 
def order_management(request):
    # Fetch all orders with related items, product variants, and images
    orders = (
        Order.objects.all()
        .prefetch_related('items__product_variant__product', 'items__product_variant__productimage_set')  
        .order_by('-order_date')
    )
    
    # Prepare the context to pass to the template
    context = {
        'orders': orders
    }
    
    # Render the template with the orders data
    return render(request, 'admin/orders/order_list.html', context)


def change_order_status(request, order_id):
    # Get the order by ID or raise a 404 error if not found
    order = get_object_or_404(Order, id=order_id)

    if request.method == 'POST':
        # Fetch the new status from the POST data
        new_status = request.POST.get('status')

        # Validate if the status is in the allowed choices
        valid_statuses = [choice[0] for choice in Order.STATUS_CHOICES]
        if new_status in valid_statuses:
            old_status = order.status  # Track the old status for feedback
            order.status = new_status  # Update the order status
            order.save()  # Save changes to the database

            # Add a success message
            messages.success(
                request,
                f"Order #{order.id} status updated from '{old_status}' to '{new_status}'."
            )
        else:
            # Add an error message for invalid status
            messages.error(request, f"Invalid status: {new_status}")

    return redirect('order_management')


@never_cache
@login_required
def admin_cancel_order(request, order_id):
    if not request.user.is_staff:
        messages.error(request, "You do not have the required permissions to cancel orders.")
        return redirect('home')

    order = get_object_or_404(Order, id=order_id)

    if order.status in ["Pending", "Processing"]:
        with transaction.atomic():  # Ensure safe database updates
            order.status = "Cancelled"
            order.save()

            # ✅ Process refund if order was paid
            if order.payment_status == "Paid":
                refund_amount = Decimal(str(order.total_amount))  # Ensure Decimal type
                
                # ✅ Get or create the user's wallet
                wallet, _ = Wallet.objects.get_or_create(user=order.user)

                # ✅ Add refunded amount to the wallet
                wallet.balance += refund_amount
                wallet.save()

                # ✅ Log the refund transaction
                Transaction.objects.create(
                    wallet=wallet,
                    amount=refund_amount,
                    transaction_type="Refund",
                    status="Completed",
                )

                messages.success(request, f"Order #{order.id} has been cancelled. ₹{refund_amount} has been refunded to the user's wallet.")
            else:
                messages.success(request, f"Order #{order.id} has been cancelled.")

    else:
        messages.error(request, "Order cannot be cancelled.")
    
    return redirect('order_management')  # Redirect to admin order management page


#####   user products  #####

@never_cache
def products(request):
    category_filter = request.GET.getlist('category', [])  # Support multiple categories
    price_min = request.GET.get('price_min', None)
    price_max = request.GET.get('price_max', None)
    sort_criteria = request.GET.get('sort', 'new_arrivals')  # Default sorting
    in_stock = request.GET.get('in_stock', None)

    # Initialize filter query
    filter_query = Q()

    # Category filter
    if category_filter:
        filter_query &= Q(category__id__in=category_filter)

    # Price filter
    price_filter_query = Q()
    if price_min and price_max:
        price_filter_query &= Q(price__gte=price_min, price__lte=price_max)
    elif price_min:
        price_filter_query &= Q(price__gte=price_min)
    elif price_max:
        price_filter_query &= Q(price__lte=price_max)

    # Stock filter
    if in_stock == "true":
        price_filter_query &= Q(stock_quantity__gt=0)

    # Filter ProductVariant and Product
    product_variants = ProductVariant.objects.filter(price_filter_query)
    product_ids = product_variants.values('product_id').distinct()
    products = Product.objects.filter(id__in=product_ids).filter(filter_query)

    # Sorting logic
    if sort_criteria == 'popularity':
        products = products.annotate(average_rating=Avg('ratings__rating')).order_by('-average_rating')
    elif sort_criteria == 'price_low_high':
        products = products.annotate(min_price=Min('productvariant__price')).order_by('min_price')
    elif sort_criteria == 'price_high_low':
        products = products.annotate(max_price=Max('productvariant__price')).order_by('-max_price')
    elif sort_criteria == 'average_ratings':
        products = products.annotate(average_rating=Avg('ratings__rating')).order_by('-average_rating')
    elif sort_criteria == 'featured':
        products = products.filter(is_featured=True)
    elif sort_criteria == 'new_arrivals':
        products = products.order_by('-created_at')
    elif sort_criteria == 'a_to_z':
        products = products.order_by('name')
    elif sort_criteria == 'z_to_a':
        products = products.order_by('-name')

    products = products.distinct()

    categories = Category.objects.all().exclude(is_deleted=True)

    return render(request, 'user/products.html', {
        'products': products,
        'categories': categories,
        'selected_categories': category_filter,
        'sort_criteria': sort_criteria,
        'show_in_stock_only': in_stock == 'true',
        'price_min': price_min,
        'price_max': price_max,
    })


@never_cache
def product_details(request, product_id, variant_id=None):
    product = get_object_or_404(Product, id=product_id, is_deleted=False)
    variants = product.productvariant_set.select_related('size', 'color').all()
    selected_variant = get_object_or_404(variants, id=variant_id) if variant_id else variants.first()
    
    # Fetch category hierarchy
    categories = []
    current_category = product.category
    while current_category:
        categories.insert(0, current_category)
        current_category = current_category.parent_category
    
    # Fetch active offers
    now = timezone.now()
    product_offer = Offer.objects.filter(offer_type='product', product=product, is_active=True,
                                         start_date__lte=now, end_date__gte=now).first()
    category_offers = Offer.objects.filter(offer_type='category', category__in=categories, is_active=True,
                                           start_date__lte=now, end_date__gte=now).order_by('-discount_value')
    category_offer = category_offers.first()
    
    # Determine the best discount
    best_offer = max(filter(None, [product_offer, category_offer]), key=lambda o: o.discount_value, default=None)
    discount_value = (selected_variant.price * (best_offer.discount_value / 100) if best_offer and best_offer.discount_type == 'percentage' 
                      else best_offer.discount_value if best_offer else 0)
    discounted_price = max(selected_variant.price - discount_value, 0)
    
    # Handle add-to-cart functionality
    if request.method == 'POST':
        variant = get_object_or_404(ProductVariant, id=request.POST.get('variant_id'))
        quantity = int(request.POST.get('quantity', 1))
        cart_item, created = Cart.objects.get_or_create(user=request.user, product_variant=variant)
        cart_item.quantity += quantity
        cart_item.price = discounted_price
        cart_item.save()
        return redirect('cart_view')
    
    # Product rating calculations
    ratings = Rating.objects.filter(product=product)
    avg_rating = ratings.aggregate(Avg('rating'))['rating__avg'] or 0
    rounded_avg_rating = round(avg_rating)
    
    # Pagination for reviews
    reviews_page = Paginator(Review.objects.filter(product=product).order_by('-created_at'), 5).get_page(request.GET.get('page'))
    
    # Related products with ratings
    related_products = Product.objects.filter(category=product.category).exclude(id=product.id)[:4]
    for related in related_products:
        related.avg_rating = Rating.objects.filter(product=related).aggregate(Avg('rating'))['rating__avg'] or 0
    
    # Fetch unique sizes and colors
    unique_sizes = ProductSize.objects.filter(productvariant__product=product).distinct().annotate(variant_count=Count('productvariant'))
    unique_color_variants = {variant.color.id: variant for variant in variants}.values()
    
        # Get unique sizes available for the product
    unique_sizes = ProductSize.objects.filter(
        productvariant__product=product,
        productvariant__color=selected_variant.color  # Filter by selected color
        ).distinct().annotate(variant_count=Count('productvariant'))
    
    color_filtered_variants = variants.filter(color=selected_variant.color)

    # Create size-to-variant mapping for selected color
    variant_map = {
        str(variant.size.id): variant.id 
        for variant in color_filtered_variants
    }

    print(f"Variant Map: {variant_map}")  # Debug output

    product_images = ProductImage.objects.filter(variant=selected_variant).distinct()

    context = {
        'product': product,
        'product_images': product_images,
        'selected_variant': selected_variant,
        'variants': variants,
        'categories': categories,
        'avg_rating': avg_rating,
        'filled_stars_range': range(rounded_avg_rating),
        'empty_stars_range': range(5 - rounded_avg_rating),
        'reviews': reviews_page,
        'related_products': related_products,
        'best_offer': best_offer,
        'discounted_price': discounted_price,
        'original_price': selected_variant.price,
        'unique_sizes': unique_sizes,
        'unique_color_variants': unique_color_variants,
        'variant_map': json.dumps(variant_map),
    }
    return render(request, 'user/product_details.html', context)


@login_required(login_url='login')
def submit_review_and_rating(request, product_id):
    """
    Handle both review and rating submission for a product and stay on the same page.
    """
    product = get_object_or_404(Product, id=product_id)

    # Initialize the forms for review and rating
    review_form = ReviewForm(request.POST or None)
    rating_value = request.POST.get('rating')  # Assuming 'rating' is the name of the rating field

    if request.method == 'POST':
        review_submitted = False
        rating_submitted = False

        # Handle the review form submission
        if review_form.is_valid():
            review = review_form.save(commit=False)
            review.user = request.user
            review.product = product
            review.save()
            review_submitted = True

        # Handle the rating submission
        if rating_value:
            # Check if a rating exists or create a new one
            rating, created = Rating.objects.update_or_create(
                user=request.user,
                product=product,
                defaults={'rating': rating_value}
            )
            rating_submitted = True

        # Determine success message based on what was submitted
        if review_submitted and rating_submitted:
            success_message = 'Review and rating submitted successfully!'
        elif review_submitted:
            success_message = 'Review submitted successfully!'
        elif rating_submitted:
            success_message = 'Rating submitted successfully!'
        else:
            success_message = 'No submission was made.'

        # Return the updated page with success or error message
        return render(request, 'user/product_details.html', {
            'product': product,
            'reviews': Review.objects.filter(product=product).order_by('-created_at'),
            'success_message': success_message,
            'review_form': ReviewForm(),  # Reset the form for next submission
            'rating_form': RatingForm(),  # Reset the rating form if you have one
        })
    else:
        # If not POST request, return the page with the initial forms
        return render(request, 'product_reviews.html', {
            'product': product,
            'reviews': Review.objects.filter(product=product).order_by('-created_at'),
            'review_form': ReviewForm(),
            'rating_form': RatingForm()  # Empty form
        })
    

@never_cache
@login_required
def profile(request):
    user = request.user
    addresses = Address.objects.filter(user=user)
    orders = (
        Order.objects.filter(user=user)
        .prefetch_related('items__product_variant__product', 'items__product_variant__productimage_set')  
        .order_by('-order_date')
    )

    print("DEBUG: Orders Retrieved ->", orders) 

    order_details = []
    for order in orders:
        print(f"DEBUG: Processing Order #{order.id} | Status -> {order.status}") 

        items = []
        for item in order.items.all():
            print(f"DEBUG: OrderItem #{item.id} | Quantity -> {item.quantity} | Price -> {item.price}")  
           
            # Fetch the first image for the product variant
            image = item.product_variant.productimage_set.first()
            items.append({
                'id': item.id,
                'product_name': item.product_variant.product.name,
                'product_image': image.image_url.url if image else None,
                'color': item.product_variant.color.color_name,
                'size': item.product_variant.size.size_name,
                'quantity': item.quantity,
                'price': item.price,
                'total_price': item.price * item.quantity,
            })

        order_details.append({
            'id': order.id,
            'status': order.status,
            'date': order.order_date,
            'total_amount': order.total_amount,
            'delivery_status': order.status,
            'payment_status': order.payment_status,  
            'payment_method': order.payment_method,  
            'items': items,
        })

    return render(request, 'user/profile.html', {
        'user': user,
        'addresses': addresses,
        'orders': order_details,
    })


@never_cache
@login_required
def edit_profile(request):
    if request.method == 'POST':
        # use the `request.POST` data to update the user instance
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated.')
            return redirect('profile')  # Redirect after successful update
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserUpdateForm(instance=request.user)

    return render(request, 'user/edit_profile.html', {'form': form})


@never_cache
@login_required
def manage_address(request):
    if request.method == 'POST':
        form = AddressForm(request.POST)
        if form.is_valid():
            address = form.save(commit=False)
            address.user = request.user
            address.save()
            messages.success(request, 'Address added successfully.')
            return redirect(f'{reverse("profile")}?tab=addresses&sidebar_tab=addresses')
    else:
        form = AddressForm()
    return render(request, 'user/manage_address.html', {'form': form})


@never_cache
@login_required
def edit_address(request, id):
    address = get_object_or_404(Address, id=id, user=request.user)
    if request.method == 'POST':
        form = AddressForm(request.POST, instance=address)
        if form.is_valid():
            form.save()
            messages.success(request, 'Address updated successfully.')
            return redirect(f'{reverse("profile")}?tab=addresses&sidebar_tab=addresses')
    else:
        form = AddressForm(instance=address)
    return render(request, 'user/edit_address.html', {'form': form})


@never_cache
@login_required
def delete_address(request, id):
    address = get_object_or_404(Address, id=id, user=request.user)
    if request.method == 'POST':
        address.delete()
        messages.success(request, 'Address deleted successfully.')
        return redirect('/profile?tab=addresses')
    return redirect('/profile?tab=addresses')


def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated.')
            return redirect('login')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'user/change_password.html', {'form': form})


def add_to_cart(request, variant_id):
    if not request.user.is_authenticated:
        messages.warning(request, "You need to log in to add items to your cart.")
        return redirect('/login/')

    variant = get_object_or_404(ProductVariant, id=variant_id)
    print(f"Adding variant to cart: {variant_id}, Size: {variant.size.size_name}")  # Debug output

    # Get or create the user's cart item for this product variant
    cart_item, created = Cart.objects.get_or_create(user=request.user, product_variant=variant)

    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 1))
        
        if quantity > variant.stock_quantity:
            return HttpResponse("Not enough stock available.", status=400)

        cart_item.quantity = quantity
        cart_item.save()
        messages.success(request, "Item added to your cart successfully.")
        return redirect('cart_view')

    return redirect('cart_view')


@never_cache
def cart_view(request):
    cart_items = Cart.get_user_cart(request.user)
    cart_data = []

    for item in cart_items:
        variant = item.product_variant
        image = ProductImage.objects.filter(variant=variant).first()
        discounted_price = variant.get_discounted_price() 

        print(f"Cart Item: {item.id}, Variant ID: {item.product_variant.id}, Size: {item.product_variant.size.size_name}")
        
        cart_data.append({
            'id': item.id,
            'product_name': item.product_variant.product.name,
            'color': item.product_variant.color.color_name,
            'size': item.product_variant.size.size_name,
            'original_price': variant.price,
            'offer_price': discounted_price,
            'quantity': item.quantity,
            'total_price': discounted_price * item.quantity, 
            'image_url': image.image_url.url if image else None,
        })

    total_price = sum(item['total_price'] for item in cart_data)
    return render(request, 'user/cart.html', {'cart_items': cart_data, 'total_price': total_price})


def update_cart(request, cart_item_id):
    cart_item = get_object_or_404(Cart, id=cart_item_id, user=request.user)
    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 1))
        if quantity > 0 and quantity <= cart_item.product_variant.stock_quantity:
            cart_item.quantity = quantity
            cart_item.save()
    return redirect('cart_view')


def remove_from_cart(request, cart_item_id):
    cart_item = get_object_or_404(Cart, id=cart_item_id, user=request.user)
    cart_item.delete()
    messages.success(request, "Item removed from the cart.")
    return redirect('cart_view')

@never_cache
@login_required
def checkout(request):
    user = request.user
    cart_items = Cart.get_user_cart(user)

    # Calculate the total price considering the offer price first
    total_price = sum(item.get_discounted_total() for item in cart_items)

    # Retrieve the coupon discount from session (if applied)
    discount = Decimal(request.session.get("discount", 0))  # Get as Decimal
    applied_coupon_code = request.session.get("applied_coupon", None)

    # Recalculate discount if a coupon is stored in the session
    if applied_coupon_code:
        try:
            coupon = Coupon.objects.get(
                coupon_code=applied_coupon_code, 
                is_active=True, 
                expiration_date__gt=timezone.now()
            )
            if total_price >= coupon.min_purchase:
                discount = coupon.calculate_discount(total_price)
                request.session["discount"] = float(discount)  # Store as float
            else:
                # Remove invalid coupon from session
                request.session.pop("applied_coupon", None)
                request.session.pop("discount", None)
                messages.error(request, "Coupon no longer valid. Minimum purchase not met.")
                discount = Decimal(0)  # Reset discount

        except Coupon.DoesNotExist:
            # Remove invalid coupon from session
            request.session.pop("applied_coupon", None)
            request.session.pop("discount", None)
            messages.error(request, "Invalid coupon code.")
            discount = Decimal(0)  # Reset discount

    # Apply final discount
    final_price = max(total_price - discount, Decimal(0))  # Use Decimal directly
    total_price_paise = int(final_price * 100)  # Convert to paise

    # Prepare cart data
    cart_data = [
        {
            'id': item.id,
            'product_name': item.product_variant.product.name,
            'color': item.product_variant.color.color_name,
            'size': item.product_variant.size.size_name,
            'price': item.product_variant.get_discounted_price(),
            'quantity': item.quantity,
            'total_price': item.get_discounted_total(),
            'image_url': ProductImage.objects.filter(variant=item.product_variant).first().image_url.url 
                        if ProductImage.objects.filter(variant=item.product_variant).exists() else None,
        }
        for item in cart_items
    ]

    # Handle POST requests (coupon & address selection)
    if request.method == "POST":
        if 'coupon_code' in request.POST:
            coupon_code = request.POST.get("coupon_code")
            try:
                coupon = Coupon.objects.get(
                    coupon_code=coupon_code,
                    is_active=True,
                    expiration_date__gt=timezone.now()
                )
                if total_price < coupon.min_purchase:
                    messages.error(request, f"Minimum purchase of ₹{coupon.min_purchase} required")
                else:
                    discount = coupon.calculate_discount(total_price)
                    request.session["applied_coupon"] = coupon_code
                    request.session["discount"] = discount  # Update session
                    applied_coupon_code = coupon_code
                    messages.success(request, f"Coupon applied! Discount: ₹{discount}")

                    # Update final price
                    final_price = max(total_price - discount, 0)
                    total_price_paise = int(final_price * 100)

            except Coupon.DoesNotExist:
                messages.error(request, "Invalid coupon code")

        # Handle address selection
        address_select = request.POST.get("address_select")
        if address_select:
            shipping_address = get_object_or_404(Address, id=address_select, user=user)
            request.session["shipping_address_id"] = shipping_address.id
            messages.success(request, "Shipping address selected successfully.")
        else:
            # Save new address if entered
            address_form = AddressForm(request.POST)
            if address_form.is_valid():
                new_address = address_form.save(commit=False)
                new_address.user = user
                new_address.save()
                request.session["shipping_address_id"] = new_address.id
                messages.success(request, "New address added and selected successfully.")
            else:
                messages.error(request, "Please correct the errors in the address form.")
                return render(request, "user/checkout.html", {
                    "cart_items": cart_data,
                    "total_price": total_price,
                    "discount": discount,
                    "final_price": final_price,
                    "total_price_paise": total_price_paise,
                    "applied_coupon": applied_coupon_code,
                    "shipping_address": shipping_address,
                    "address_form": address_form,  
                })

    # Get the selected shipping address
    selected_address_id = request.session.get("shipping_address_id")
    shipping_address = Address.objects.filter(id=selected_address_id, user=user).first()

    # Create Razorpay order only
    razorpay_order_id = None
    order = None
    if shipping_address and request.method == "POST":
        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        try:
            razorpay_order = client.order.create({
                'amount': total_price_paise,
                'currency': 'INR',
                'payment_capture': '1',
            })
            razorpay_order_id = razorpay_order['id']
            # Save the order
            order = Order.objects.create(
                user=user,
                subtotal=total_price,  # Ensure subtotal is passed here
                total_amount=final_price,
                payment_status="Pending",
                razorpay_order_id=razorpay_order_id,
                status="Initiated",
                shipping_address=shipping_address
            )

            # Save each item in order
            for cart_item in cart_items:
                OrderItem.objects.create(
                    order=order,
                    product_variant=cart_item.product_variant,
                    quantity=cart_item.quantity,
                    price=cart_item.product_variant.get_discounted_price(),
                )
        except Exception as e:
            messages.error(request, f"Payment gateway error: {str(e)}")
    
    # Get wallet balance
    wallet_balance = user.wallet.balance if hasattr(user, 'wallet') else Decimal(0)

    return render(request, "user/checkout.html", {
        "cart_items": cart_data,
        "total_price": total_price,
        "discount": discount,
        "final_price": final_price,
        "total_price_paise": total_price_paise,
        "applied_coupon": applied_coupon_code,
        "shipping_address": shipping_address,
        "razorpay_order_id": razorpay_order_id,
        "razorpay_key_id": settings.RAZORPAY_API_KEY,
        "address_form": AddressForm(),
        "wallet_balance": wallet_balance,
        "order": order, 
    })


@never_cache
@login_required
@transaction.atomic
def place_order(request):
    user = request.user
    cart_items = Cart.objects.filter(user=user)

    if not cart_items.exists():
        messages.error(request, "Your cart is empty.")
        return redirect("checkout")

    # --- Price Calculations ---
    original_subtotal = sum(
        Decimal(item.product_variant.price) * item.quantity 
        for item in cart_items
    )
    offer_subtotal = sum(item.get_discounted_total() for item in cart_items)
    offer_discount = original_subtotal - offer_subtotal

    coupon_discount = Decimal(0)
    applied_coupon_code = request.session.get("applied_coupon")
    applied_coupon = None
    if applied_coupon_code:
        try:
            applied_coupon = Coupon.objects.get(
                coupon_code=applied_coupon_code,
                is_active=True,
                expiration_date__gt=timezone.now()
            )
            if offer_subtotal >= applied_coupon.min_purchase:
                if applied_coupon.discount_type == "percentage":
                    coupon_discount = (applied_coupon.discount_value / 100) * offer_subtotal
                else:
                    coupon_discount = Decimal(applied_coupon.discount_value)
                coupon_discount = min(coupon_discount, offer_subtotal)
            else:
                request.session.pop("applied_coupon", None)
                request.session.pop("discount", None)
                messages.error(request, "Coupon minimum purchase not met")
                coupon_discount = Decimal(0)
        except Coupon.DoesNotExist:
            request.session.pop("applied_coupon", None)
            request.session.pop("discount", None)
            messages.error(request, "Invalid coupon code")
            coupon_discount = Decimal(0)

    total_discount = offer_discount + coupon_discount
    final_amount = original_subtotal - total_discount
    request.session["final_price"] = str(final_amount)

    if request.method == "POST":
        payment_method = request.POST.get("payment_method", "cod")

        
        shipping_address_id = request.session.get("shipping_address_id")
        if not shipping_address_id:
            messages.error(request, "Please select a shipping address.")
            return redirect("checkout")
        shipping_address = get_object_or_404(Address, id=shipping_address_id, user=user)

        # --- Create Order ---
        order = Order.objects.create(
            user=user,
            shipping_address=shipping_address,
            subtotal=original_subtotal,
            discount=total_discount,
            total_amount=final_amount,
            applied_coupon=applied_coupon,
            status="Payment Pending",
            payment_status="Pending",
            payment_method=payment_method,
        )

        if payment_method == "cod":
            if final_amount > Decimal(1000):
                messages.error(request, "Orders above Rs 1000 are not allowed for Cash on Delivery.")
                return redirect("checkout")
            else:
                # Mark COD as successful
                order.payment_status = "Pending"  # Payment collected on delivery
                order.status = "Confirmed"
                order.save()
                payment_success = True


        # --- Create Order Items (without stock reduction) ---
        for cart_item in cart_items:
            OrderItem.objects.create(
                order=order,
                product_variant=cart_item.product_variant,
                quantity=cart_item.quantity,
                price=cart_item.product_variant.get_discounted_price(),
            )

        # --- Payment Processing ---
        payment_success = False

        if payment_method == "razorpay":
            razorpay_payment_id = request.POST.get("razorpay_payment_id", "")
            
            if razorpay_payment_id.startswith('failed_'):
                # Failed payment from modal retry
                messages.error(request, "Payment failed. Order saved as pending.")
            else:
                try:
                    client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
                    client.utility.verify_payment_signature({
                        'razorpay_order_id': request.POST.get("razorpay_order_id"),
                        'razorpay_payment_id': razorpay_payment_id,
                        'razorpay_signature': request.POST.get("razorpay_signature")
                    })

                    #  Save Payment ID
                    order.razorpay_payment_id = razorpay_payment_id
                    order.payment_status = "Paid"
                    order.status = "Processing"
                    order.save()

                    payment_success = True
                except Exception as e:
                    messages.error(request, f"Payment failed: {str(e)}")

        elif payment_method == "wallet":
            wallet = user.wallet  # Access the wallet through the related field
            if wallet.balance >= final_amount:
                # Deduct from wallet
                wallet.debit(final_amount)
                # Create a transaction record
                Transaction.objects.create(
                    wallet=wallet,
                    amount=final_amount,
                    transaction_type="Debit",
                    status="Completed",
                    created_at=now(),
                )
                payment_success = True
                order.payment_status = "Paid"
                order.status = "Processing"
                messages.success(request, "Payment successful using wallet. Please try another payment method.")
            else:
                messages.error(request, "Insufficient wallet balance.")
                return redirect("payment_pending", order_id=order.id)


        # --- Update Order Status & Stock ---
        if payment_success:
            # Reduce stock only after successful payment
            for item in order.items.all():
                variant = item.product_variant
                variant.stock_quantity -= item.quantity
                variant.save()

            # Mark coupon as used
            if applied_coupon:
                UserCouponUsage.objects.create(user=user, coupon=applied_coupon, order=order)
                applied_coupon.used_count += 1
                applied_coupon.save()

            messages.success(request, "Order placed successfully!")
        else:
            messages.warning(request, "Payment failed. Order saved as pending.")

        order.save()

        # --- Cleanup ---
        if payment_success:
            # Delete cart items within the transaction
            cart_items.delete()
            # Clear session data
            keys_to_remove = ["applied_coupon", "discount", "final_price", "shipping_address_id"]
            for key in keys_to_remove:
                if key in request.session:
                    del request.session[key]

        if payment_success:
            return redirect("order_summary", order_id=order.id)
        else:
            return redirect("payment_pending", order_id=order.id)

    return render(request, "user/place_order.html", {
        "cart_items": cart_items,
        "subtotal": original_subtotal,
        "total_discount": total_discount,
        "final_price": final_amount,
    })


@never_cache
@login_required
def order_summary(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    order_items = order.items.all().select_related('product_variant').prefetch_related('product_variant__productimage_set')

    order_data = []
    for item in order_items:
        image = item.product_variant.productimage_set.first()
        original_price = item.product_variant.price  
        discounted_price = item.price                
        total_price = discounted_price * item.quantity
        total_savings = (original_price - discounted_price) * item.quantity

        # Calculate total savings by offers so far as a Decimal:
        total_savings_by_offers = sum((x['total_savings'] for x in order_data), Decimal(0))
        # add the coupon discount (which is a Decimal) without converting to float:
        total_savings_with_coupon = total_savings_by_offers + order.discount

        order_data.append({
            'product_name': item.product_variant.product.name,
            'color': item.product_variant.color.color_name,
            'size': item.product_variant.size.size_name,
            'original_price': original_price,
            'discounted_price': discounted_price,
            'quantity': item.quantity,
            'total_price': total_price,
            'total_savings': total_savings,
            'image_url': image.image_url.url if image else None,
            "total_savings_with_coupon": total_savings_with_coupon,
            "total_savings_by_offers": total_savings_by_offers,
        })

    applied_coupon = order.applied_coupon
    discount = order.get_discount_amount()
    final_amount = order.get_final_amount()

    return render(request, "user/order_summary.html", {
        "order": order,
        "order_items": order_data,
        "applied_coupon": applied_coupon,
        "discount": discount,
        "final_amount": final_amount,
    })


@never_cache
@login_required
def retry_payment(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user, payment_status="Pending")
    
    # Create new Razorpay order
    client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
    try:
        razorpay_order = client.order.create({
            'amount': int(order.total_amount * 100),
            'currency': 'INR',
            'payment_capture': '1'
        })
        order.razorpay_order_id = razorpay_order['id']
        order.save()
    except Exception as e:
        messages.error(request, f"Payment gateway error: {str(e)}")
        return redirect("order_summary", order_id=order.id)

    return render(request, "user/retry_payment.html", {
        'order': order,
        'razorpay_order_id': razorpay_order['id'],
        'key_id': settings.RAZORPAY_API_KEY,
        'amount': order.total_amount,
    })


@csrf_exempt
def verify_payment(request):
    if request.method == "POST":
        data = json.loads(request.body)
        order_id = data.get('order_id')
        
        order = get_object_or_404(Order, id=order_id)
        
        if verify_razorpay_payment(
            data['razorpay_order_id'],
            data['razorpay_payment_id'],
            data['razorpay_signature']
        ):
            # Payment successful
            # - clear cart
            Cart.objects.filter(user=order.user).delete()
            
            # Update order status
            order.payment_status = "Paid"
            order.status = "Processing"
            order.razorpay_payment_id = data['razorpay_payment_id']
            
            # Reduce stock
            for item in order.items.all():
                variant = item.product_variant
                variant.stock_quantity -= item.quantity
                variant.save()
            
            order.save()
            return JsonResponse({'success': True})
            
        return JsonResponse({'success': False})


@never_cache
@login_required
def payment_pending(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user, payment_status="Pending")

    return render(request, "user/payment_pending.html", {"order": order})

    
@login_required
def user_cancel_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if order.status in ["Pending", "Processing"]:  # Check if order is cancellable
        with transaction.atomic():  # Ensure atomicity for database updates
            order.status = "Cancelled"
            order.save()

            #  Refund logic: Check if the order was paid
            if order.payment_status == "Paid":
                refund_amount = Decimal(str(order.total_amount))  # Ensure Decimal type
                
                #  Get or create user's wallet
                wallet, _ = Wallet.objects.get_or_create(user=request.user)
                
                # Add refunded amount to the wallet
                wallet.balance = Decimal(str(wallet.balance)) + refund_amount

                wallet.save()

                # Log the refund transaction
                Transaction.objects.create(
                    wallet=wallet,
                    amount=refund_amount,
                    transaction_type="Refund",
                    status="Completed",
                )

                messages.success(request, f"Your order has been cancelled. ₹{refund_amount} has been refunded to your wallet.")
            else:
                messages.success(request, "Your order has been cancelled.")

    else:
        messages.error(request, "This order cannot be cancelled.")

    return redirect("profile")  # Redirect to user profile or orders page


# -------------- OFFER MANAGEMENT -------------- #
@never_cache
@require_http_methods(["GET"])
def offer_list(request):
    """
    Render the offer list page.
    """
    return render(request, "admin/orders/offer_list.html")


@never_cache
@require_http_methods(["GET"])
def get_offers(request):
    """
    API endpoint to fetch all regular offers (product and category offers).
    """
    offers = Offer.objects.all().order_by("-id")
    offer_list = []

    for offer in offers:
        offer_data = {
            "id": offer.id,
            "type": offer.offer_type,
            "discount": offer.discount_value, 
            "valid": offer.is_active,
            "product": offer.product.name if offer.product else None,
            "category": offer.category.category_name if offer.category else None,
            "min_purchase": offer.min_purchase,
            "start_date": offer.start_date.strftime("%Y-%m-%d %H:%M"),
            "end_date": offer.end_date.strftime("%Y-%m-%d %H:%M"),
        }
        offer_list.append(offer_data)

    return JsonResponse(offer_list, safe=False)


@require_GET
def get_referral_offers(request):
    referrals = Referral.objects.select_related("referrer", "referred_user").all().order_by("-id")
    referral_offer = ReferralOffer.objects.first()  # Assuming a single referral offer exists
    reward_amount = referral_offer.reward_amount if referral_offer else 0  # Default to 0 if no offer

    referral_list = []
    for referral in referrals:
        referral_data = {
            "id": referral.id,
            "referrer": {"id": referral.referrer.id, "username": referral.referrer.username},
            "referred_user": {"id": referral.referred_user.id, "username": referral.referred_user.username},
            "reward_amount": str(reward_amount),  # Convert Decimal to string for JSON serialization
            "reward_claimed": referral.reward_claimed,
        }
        referral_list.append(referral_data)

    return JsonResponse(referral_list, safe=False)


@require_http_methods(["DELETE"])  
def delete_offer(request, offer_id):
    """
    API endpoint to delete an offer.
    """
    try:
        offer = get_object_or_404(Offer, id=offer_id)
        offer.delete()
        return JsonResponse({"message": "Offer deleted successfully!"}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@require_http_methods(["GET", "POST"])
def create_offer(request):
    if request.method == "GET":
        products = Product.objects.all()
        categories = Category.objects.all().exclude(is_deleted=True)
        return render(request, "admin/orders/create_offer.html", {"products": products, "categories": categories})

    elif request.method == "POST":
        try:
            data = request.POST
            print("Received data:", data)  # Debugging line

            offer_type = data.get("offer_type")
            discount = float(data.get("discount") or 0)
            min_purchase = float(data.get("min_purchase") or 0)
            reward_amount = float(data.get("reward_amount") or 0)  # For referral offer

            #  Use default dates if missing
            start_date_str = data.get("start_date")
            end_date_str = data.get("end_date")

            start_date = timezone.datetime.fromisoformat(start_date_str) if start_date_str else timezone.now()
            end_date = timezone.datetime.fromisoformat(end_date_str) if end_date_str else start_date + timezone.timedelta(days=30)

            is_active = data.get("is_active", "true").lower() == "true"

            product = get_object_or_404(Product, id=data["product_id"]) if data.get("product_id") else None
            category = get_object_or_404(Category, id=data["category_id"]) if data.get("category_id") else None

            #  Create the offer
            offer = Offer.objects.create(
                offer_type=offer_type,
                discount_value=discount,
                product=product,
                category=category,
                min_purchase=min_purchase,
                start_date=start_date,
                end_date=end_date,
                is_active=is_active,
            )

            #  If it's a referral offer, just store the reward amount
            if offer_type == "referral":
                ReferralOffer.objects.create(
                    offer=offer,
                    reward_amount=reward_amount,
                )
                print(f" Referral Offer Created | Reward Amount: {reward_amount}")

            return JsonResponse({"message": "Offer created successfully!", "id": offer.id})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)      

@require_http_methods(["POST"])
def toggle_offer_status(request, offer_id):
    """ Activate or deactivate an offer """
    offer = get_object_or_404(Offer, id=offer_id)
    offer.is_active = not offer.is_active
    offer.save()
    status = "activated" if offer.is_active else "deactivated"
    return JsonResponse({"message": f"Offer {status}"})


# -------------- COUPON MANAGEMENT -------------- #

@never_cache
def coupon_list(request):
    page_number = request.GET.get('page', 1)  # Get the current page from the query parameters
    items_per_page = 10  # Define how many coupons to show per page (adjust as needed)
    search_query = request.GET.get('search', '')  # Get the search query from the request
    
    # Filter coupons based on the search query
    coupons = Coupon.objects.filter(is_active=True, expiration_date__gte=timezone.now())
    if search_query:
        coupons = coupons.filter(coupon_code__icontains=search_query)  # Filter by coupon code
        

    # Use Paginator to paginate the coupons
    paginator = Paginator(coupons, items_per_page)
    page = paginator.get_page(page_number)

    # Handle AJAX request for paginated results
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' and request.method == "GET":
        data = [
            {
                "id": c.id,
                "coupon_code": c.coupon_code,
                "discount_value": float(c.discount_value),
                "min_purchase": float(c.min_purchase),
                "valid": c.is_valid(),
                "usage_limit": c.usage_limit,
                "used_count": c.used_count,
                "expiration_date": c.expiration_date.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for c in page.object_list  # Only include coupons for the current page
        ]
        
        response_data = {
            "coupons": data,
            "has_next": page.has_next(),
            "has_previous": page.has_previous(),
            "next_page_number": page.next_page_number() if page.has_next() else None,
            "previous_page_number": page.previous_page_number() if page.has_previous() else None,
        }
        return JsonResponse(response_data, safe=False)

    # Regular page rendering for first load or page navigation
    return render(request, 'admin/orders/coupon_list.html', {'coupons': page})


@never_cache
def add_coupon(request): 
    if request.method == 'POST':
        coupon_code = request.POST.get('coupon_code')
        discount_type = request.POST.get('discount_type')  
        discount_value = request.POST.get('discount_value')
        max_discount = request.POST.get('max_discount')
        min_purchase = request.POST.get('min_purchase')
        usage_limit = request.POST.get('usage_limit')
        per_user_limit = request.POST.get('per_user_limit')
        expiration_date = request.POST.get('expiration_date')
        allowed_categories = request.POST.getlist('allowed_categories')
        allowed_users = request.POST.getlist('allowed_users')  

        # Fallback to 'fixed' if discount_type is not provided
        if not discount_type:
            discount_type = 'fixed'

        # Creating the coupon instance
        coupon = Coupon(
            coupon_code=coupon_code,
            discount_type=discount_type,
            discount_value=discount_value,
            max_discount=max_discount,
            min_purchase=min_purchase,
            usage_limit=usage_limit,
            per_user_limit=per_user_limit,
            expiration_date=expiration_date,
        )
        coupon.save()
        
        # Add allowed categories and users to the coupon
        coupon.allowed_categories.set(allowed_categories)
        coupon.allowed_users.set(allowed_users)
        
        return redirect('coupon_list')  # Redirect to coupon list after creation

    categories = Category.objects.all() 
    users = CustomUser.objects.all() 
    return render(request, 'admin/orders/add_coupon.html', {'categories': categories, 'users': users})


@never_cache
def edit_coupon(request, coupon_id):
    coupon = get_object_or_404(Coupon, id=coupon_id)
    if request.method == 'POST':
        coupon.coupon_code = request.POST.get('coupon_code')
        coupon.discount_type = request.POST.get('discount_type')
        coupon.discount_value = request.POST.get('discount_value')
        coupon.max_discount = request.POST.get('max_discount')
        coupon.min_purchase = request.POST.get('min_purchase')
        coupon.usage_limit = request.POST.get('usage_limit')
        coupon.per_user_limit = request.POST.get('per_user_limit')
        coupon.expiration_date = request.POST.get('expiration_date')
        coupon.allowed_categories.set(request.POST.getlist('allowed_categories'))
        coupon.allowed_users.set(request.POST.getlist('allowed_users'))
        coupon.save()
        return redirect('coupon_list')
    
    categories = Category.objects.all()
    users = CustomUser.objects.all()
    return render(request, 'coupon/edit_coupon.html', {'coupon': coupon, 'categories': categories, 'users': users})


def delete_coupon(request, coupon_id):
    coupon = get_object_or_404(Coupon, id=coupon_id)
    coupon.delete()  # Delete the coupon
    return redirect('coupon_list')  # Redirect to the coupon list page


@require_http_methods(["POST"])
def validate_coupon(request):
    try:
        data = json.loads(request.body)
        coupon_code = data.get("coupon_code")
        print(f"Coupon validation triggered for: {coupon_code}")
        order_total = Decimal(data.get("order_total", 0))  # Convert to Decimal for consistency

        coupon = Coupon.objects.get(
            coupon_code=coupon_code,
            is_active=True,
            expiration_date__gt=timezone.now()
        )

        # Check temporary usage
        temp_usage = request.session.get('temp_coupon_usage', {})
        temp_count = temp_usage.get(coupon_code, 0)

        if (coupon.used_count + temp_count) >= coupon.usage_limit:
            return JsonResponse({"error": "Coupon usage limit reached"}, status=400)

        if order_total < Decimal(coupon.min_purchase):
            return JsonResponse({"error": f"Minimum purchase of ₹{coupon.min_purchase} required"}, status=400)

        # Calculate actual discount
        if coupon.discount_type == "fixed":
            discount = min(Decimal(coupon.discount_value), order_total)
        elif coupon.discount_type == "percentage":
            discount = (Decimal(coupon.discount_value) / Decimal(100)) * order_total
            if coupon.max_discount:
                discount = min(discount, Decimal(coupon.max_discount))

        #  Convert `discount` to float before subtraction to prevent type errors
        discount_float = float(discount)
        new_total = float(order_total) - discount_float  # Ensure both are floats

        #  Save coupon code and discount to session
        request.session["applied_coupon"] = coupon_code  # Store applied coupon
        request.session["discount"] = str(discount) # Ensure it's saved as a string
        request.session["final_price"] = str(new_total)  # Save new total after discount
        request.session.modified = True  # Ensure session updates are saved

        #  Generate a new Razorpay order with updated amount
        client = razorpay.Client(auth=(settings.RAZORPAY_API_KEY, settings.RAZORPAY_API_SECRET))
        razorpay_order = client.order.create({
            "amount": int(new_total * 100),  # Razorpay expects amount in paise
            "currency": "INR",
            "payment_capture": 1  # Auto-capture payment
        })
        new_razorpay_order_id = razorpay_order["id"]

        return JsonResponse({
            "message": "Coupon valid",
            "discount": discount_float,  #  Send discount as float
            "coupon_code": coupon_code,
            "razorpay_order_id": new_razorpay_order_id,  # Updated order ID
        })

    except Coupon.DoesNotExist:
        return JsonResponse({"error": "Invalid coupon"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
    

@never_cache
def sales_report(request):
    """Handles sales report filtering and downloading."""
    filter_type = request.GET.get('filter', 'daily')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    today = timezone.now().date()

    if filter_type == "daily":
        start_date = end_date = today
        truncate_by = 'day'
    elif filter_type == "weekly":
        start_date = today - datetime.timedelta(days=7)
        end_date = today
        truncate_by = 'day'
    elif filter_type == "monthly":
        start_date = today.replace(day=1)
        end_date = today
        truncate_by = 'day'
    elif filter_type == "yearly":
        start_date = today.replace(month=1, day=1)
        end_date = today
        truncate_by = 'month'
    elif filter_type == "custom" and start_date and end_date:
        start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
        end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()
        truncate_by = 'day'
    else:
        start_date = end_date = today
        truncate_by = 'day'

    # Filter orders based on date range
    orders = Order.objects.filter(order_date__date__range=[start_date, end_date])

    # Aggregate data for the chart
    sales_data = (
        orders.annotate(date=TruncDay('order_date'))
        .values('date')
        .annotate(total_sales=Sum('total_amount'))
        .order_by('date')
    )

    # Convert data to JSON format for Chart.js
    sales_chart_labels = [entry["date"].strftime("%Y-%m-%d") for entry in sales_data]
    sales_chart_values = [float(entry["total_sales"]) for entry in sales_data]  # Convert Decimal to float

    top_products, top_categories = get_sales_analytics()

    context = {
        'orders': orders,
        'total_orders': orders.count(),
        'total_sales': float(orders.aggregate(Sum('total_amount'))['total_amount__sum'] or 0),  # Convert Decimal to float
        'total_discount': float(orders.aggregate(Sum('discount'))['discount__sum'] or 0),  # Convert Decimal to float
        'filter_type': filter_type,
        'start_date': start_date,
        'end_date': end_date,
        'sales_chart_labels': json.dumps(sales_chart_labels),
        'sales_chart_values': json.dumps(sales_chart_values),
        'top_products': top_products,
        'top_categories': top_categories,
    }

    return render(request, 'admin/sales_report.html', context)


def download_sales_report(request, report_type):
    """Exports sales report to PDF or Excel."""
    filter_type = request.GET.get('filter', 'daily')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    today = timezone.now().date()

    try:
        if filter_type == "daily":
            start_date = end_date = today
        elif filter_type == "weekly":
            start_date = today - datetime.timedelta(days=7)
            end_date = today
        elif filter_type == "monthly":
            start_date = today.replace(day=1)
            end_date = today
        elif filter_type == "yearly":
            start_date = today.replace(month=1, day=1)
            end_date = today
        elif filter_type == "custom" and start_date and end_date:
            start_date = parser.parse(start_date).date()
            end_date = parser.parse(end_date).date()
        else:
            start_date = end_date = today
    except ValueError:
        return JsonResponse({"error": "Invalid date format"}, status=400)

    orders = Order.objects.filter(order_date__date__range=[start_date, end_date])

    # PDF Export with Table
    if report_type == "pdf":
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="sales_report.pdf"'

        pdf = SimpleDocTemplate(response, pagesize=letter)
        elements = []
        
        data = [["Order ID", "Order Date", "Total Amount", "Discount"]]  # Table Header
        for order in orders:
            data.append([order.id, order.order_date.strftime('%Y-%m-%d'), f"${order.total_amount}", f"${order.discount}"])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        
        elements.append(table)
        pdf.build(elements)
        return response

    # Excel Export
    elif report_type == "excel":
        if orders.exists():
            data = []
            for order in orders:
                data.append({
                    "ID": order.id,
                    "Order Date": order.order_date.astimezone(dt_timezone.utc).replace(tzinfo=None),  # ✅ Fixed
                    "Total Amount": order.total_amount,
                    "Discount": order.discount,
                })

            df = pd.DataFrame(data)
        else:
            df = pd.DataFrame(columns=["ID", "Order Date", "Total Amount", "Discount"])

        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="sales_report.xlsx"'
        df.to_excel(response, index=False)
        return response

    return JsonResponse({"error": "Invalid report type"}, status=400)


@never_cache
@login_required
def wishlist_view(request):
    wishlist_items = Wishlist.objects.filter(user=request.user)

    wishlist_data = []
    for item in wishlist_items:
        variant = item.product_variant
        image = ProductImage.objects.filter(variant=variant).first()

        wishlist_data.append({
            'id': item.id,
            'variant_id': variant.id,  # Ensure this is passed correctly
            'product_name': variant.product.name,
            'color': variant.color.color_name,
            'size': variant.size.size_name,
            'price': variant.price,
            'image_url': image.image_url.url if image else None,
        })

    return render(request, 'user/wishlist.html', {
        'wishlist_items': wishlist_data,  # Only passing wishlist items
    })


@login_required
def wishlist_item_count(request):
    """ Return the total wishlist item count dynamically """
    wishlist_count = Wishlist.objects.filter(user=request.user).count()
    return JsonResponse({"wishlist_count": wishlist_count})

@login_required
def add_to_wishlist(request, variant_id):
    product_variant = get_object_or_404(ProductVariant, id=variant_id)
    wishlist_item, created = Wishlist.objects.get_or_create(user=request.user, product_variant=product_variant)

    if created:
        message = "Item added to wishlist."
    else:
        message = "Item is already in your wishlist."

    return redirect('wishlist_view')  # Redirect to the wishlist page


@login_required
def add_to_cart_from_wishlist(request, variant_id):
    variant = get_object_or_404(ProductVariant, id=variant_id)

    # Get or create the cart item
    cart_item, created = Cart.objects.get_or_create(user=request.user, product_variant=variant)

    if created:
        cart_item.quantity = 1  # Default quantity
    else:
        if cart_item.quantity < variant.stock_quantity:
            cart_item.quantity += 1  # Increase quantity
        else:
            return HttpResponse("Not enough stock.", status=400)

    cart_item.save()

    # Remove the item from the wishlist after adding to cart
    Wishlist.objects.filter(user=request.user, product_variant=variant).delete()

    return redirect('cart_view')  # Redirect to cart view


@login_required
def remove_from_wishlist(request):
    if request.method == "POST":
        item_id = request.POST.get("item_id")
        wishlist_item = get_object_or_404(Wishlist, id=item_id, user=request.user)
        wishlist_item.delete()
        return JsonResponse({"status": "removed"})

    return JsonResponse({"status": "error"}, status=400)


@login_required
def wallet_view(request):
    # Get or create the wallet of the logged-in user
    wallet, created = Wallet.objects.get_or_create(user=request.user)

    # Fetch transactions related to the wallet (ordered by latest first)
    transactions = Transaction.objects.filter(wallet=wallet).order_by("-created_at")

    # Render the wallet page with balance and transactions
    return render(request, "user/wallet.html", {
        "wallet": wallet,
        "transactions": transactions,
    })


#----------  RETURN MANAGEMENT -------------------------

#  Helper function to check if user is admin
def is_admin(user):
    return user.is_staff


@login_required
def request_return(request, order_item_id):
    """Allow users to request a return with a predefined reason and optional additional notes."""
    
    order_item = get_object_or_404(OrderItem, id=order_item_id, order__user=request.user)

    if request.method == "POST":
        reason_id = request.POST.get("reason")
        additional_notes = request.POST.get("additional_notes", "").strip()

        reason = ReturnReason.objects.get(id=reason_id) if reason_id else None

        # Check if a return request already exists for this order item
        if ReturnRequest.objects.filter(order_item=order_item).exists():
            messages.error(request, "You have already submitted a return request for this item.")
            return redirect("user_returns")  

        # Create a new return request
        ReturnRequest.objects.create(
            order_item=order_item,
            user=request.user,
            reason=reason,
            additional_notes=additional_notes if additional_notes else None,
            status="Pending",
            created_at=now(),
        )

        messages.success(request, "Return request submitted successfully!")
        return redirect("user_returns")  

    # Fetch all predefined return reasons
    reasons = ReturnReason.objects.all()
    return render(request, "user/request_return.html", {"order_item": order_item, "reasons": reasons})


#  User: View their return requests
@login_required
def user_return_requests(request):
    """Display the return requests submitted by the user."""
    
    returns = ReturnRequest.objects.filter(user=request.user)
    return render(request, "user/users_return.html", {"returns": returns})


#  Admin: View all return requests
@login_required
@user_passes_test(is_admin)
def admin_return_requests(request):
    returns = ReturnRequest.objects.all()
    return render(request, "admin/orders/admin_return.html", {"returns": returns})


@csrf_exempt  # Allows AJAX POST requests
def update_return_status(request):
    if request.method == "POST":
        return_id = request.POST.get("return_id")
        new_status = request.POST.get("new_status")

        try:
            return_request = ReturnRequest.objects.get(id=return_id)
            order_item = return_request.order_item  
            order = order_item.order
            
            # Update return status
            return_request.status = new_status
            return_request.save()

            # ✅ Process refund if return is approved and order was paid
            if new_status == "Approved" and order.payment_status == "Paid":
                refund_amount = Decimal(str(order_item.price))  # Ensure Decimal type
                
                # ✅ Get or create the user's wallet
                wallet, _ = Wallet.objects.get_or_create(user=order.user)

                # ✅ Add refunded amount to the wallet
                wallet.balance += refund_amount
                wallet.save()

                # ✅ Log the refund transaction
                Transaction.objects.create(
                    wallet=wallet,
                    amount=refund_amount,
                    transaction_type="Refund",
                    status="Completed",
                )

                return JsonResponse({
                    "message": f"Return approved. ₹{refund_amount} has been refunded to the user's wallet."
                }, status=200)

            return JsonResponse({"message": "Return status updated successfully!"}, status=200)

        except ReturnRequest.DoesNotExist:
            return JsonResponse({"message": "Return request not found."}, status=404)

    return JsonResponse({"message": "Invalid request"}, status=400)


def download_invoice(request, order_id):
    """
    Generate and download an invoice PDF for a given order.
    """
    # Retrieve the order (adjust as per your model)
    order = get_object_or_404(Order, id=order_id)
    order_items = order.items.all()  # Using the related name "items" from OrderItem

    # Create the HttpResponse with PDF headers.
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="invoice_{order.id}.pdf"'

    # Create a PDF document using SimpleDocTemplate
    doc = SimpleDocTemplate(response, pagesize=letter)
    elements = []
    
    # Get a set of styles to use for text
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    normal_style = styles['Normal']
    heading_style = styles['Heading2']
    
    # Invoice Title and Order Summary
    elements.append(Paragraph("Invoice", title_style))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>Order ID:</b> {order.id}", normal_style))
    elements.append(Paragraph(f"<b>Status:</b> {order.status}", normal_style))
    elements.append(Spacer(1, 12))
    
    # Shipping Address
    elements.append(Paragraph("Shipping Address:", heading_style))
    shipping = order.shipping_address
    shipping_text = (
        f"{shipping.address_line1}<br/>"
        f"{shipping.city}, {shipping.state} {shipping.postal_code}<br/>"
        f"{shipping.country}"
    )
    elements.append(Paragraph(shipping_text, normal_style))
    elements.append(Spacer(1, 12))
    
    # Order Items Table
    data = [["Product", "Color", "Size", "Unit Price", "Quantity", "Total"]]
    for item in order_items:
        # Retrieve the discounted price from the product variant
        unit_price = item.product_variant.get_discounted_price()
        total_price = unit_price * item.quantity
        
        # With the __str__ method defined, these will show the correct values.
        color = item.product_variant.color
        size = item.product_variant.size
        
        data.append([
            item.product_variant.product.name,
            str(color), 
            str(size),   
            f"₹{unit_price}",
            item.quantity,
            f"₹{total_price}"
        ])
    
    table = Table(data, hAlign="LEFT")
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))
    
    # Order Totals (subtotal, coupon info if any, grand total)
    elements.append(Paragraph(f"<b>Subtotal:</b> ₹{order.subtotal}", normal_style))
    if hasattr(order, 'applied_coupon') and order.applied_coupon:
        elements.append(Paragraph(f"<b>Coupon Applied:</b> {order.applied_coupon.coupon_code}", normal_style))
    elements.append(Paragraph(f"<b>Grand Total:</b> ₹{order.total_amount}", normal_style))
    
    # Build PDF
    doc.build(elements)
    return response

