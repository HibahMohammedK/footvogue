from django.shortcuts import render, redirect, get_object_or_404
from .models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout
from django.views.decorators.cache import never_cache
import logging
from django.contrib.auth.decorators import login_required
from .forms import ReviewForm, RatingForm
from django.core.paginator import Paginator
from django.db.models import Avg, Sum, Count
from .utils import generate_and_send_otp 
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.urls import reverse
from django.http import HttpResponse
from django.db import transaction
from django.contrib.messages import success, error
from django.http import JsonResponse
import json
from django.views.decorators.http import require_http_methods
from dateutil import parser

   

@never_cache
def home(request):
    # Fetch products from the database
    products = Product.objects.prefetch_related(
        'productvariant_set__productimage_set'
    ).filter(is_deleted=False)  # Adjust filters based on your requirements

    # Create a rating range (1 to 5) for use in the template
    rating_range = range(1, 6)

    # Fetch cart items for the logged-in user
    cart_items = []
    total_price = 0

    if request.user.is_authenticated:
        # Retrieve all cart items for the logged-in user
        cart_items = Cart.objects.filter(user=request.user)
        
        # Calculate the total price of items in the cart
        total_price = sum(item.quantity * item.product_variant.price for item in cart_items)

        for item in cart_items:
            # Retrieve the first image for the variant
            image = ProductImage.objects.filter(variant=item.product_variant).first()
            item.image_url = image.image_url.url if image else None


    
    context = {
        'products': products, 
        'rating_range': rating_range,
        'cart_items': cart_items,
        'total_price': total_price,
    }

    # Render the home template with products and rating range
    return render(request, 'user/home.html', context)

@never_cache
def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username").strip()
        email = request.POST.get("email").strip()
        password = request.POST.get("password").strip()
        confirm_password = request.POST.get("confirm_password").strip()

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
            is_verified=False
        )
        user.save()

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




# Logout View
def logout_view(request):
    logout(request)
    return redirect('home')

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



### admin view ###

# Admin Dashboard Home
@never_cache
@login_required
def admin_dash(request):
    if not request.user.is_superuser:
        return redirect('login')  # Ensure only admin can access

    # Render the admin dashboard template
    return render(request, 'admin/admin_dash.html')



# Admin Dashboard - List Users with Search Functionality
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


# Unblock User
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


from .forms import *

def category_list(request):
    categories = Category.objects.filter(is_deleted=False)
    return render(request, 'admin/categories/category_list.html', {'categories': categories})

def add_category(request):
    if request.method == 'POST':
        category_name = request.POST.get('category_name')  # Get the category name
        parent_category_id = request.POST.get('parent_category')  # Get the parent category ID
        
        # Check if a category with the same name already exists and is soft-deleted
        existing_category = Category.objects.filter(category_name=category_name, is_deleted=True).first()
        
        if existing_category:
            # If the category exists but is soft-deleted, restore it
            existing_category.is_deleted = False
            existing_category.save()
            messages.success(request, f"Category '{category_name}' restored successfully!")
        else:
            # If no such soft-deleted category exists, create a new one
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
    if request.method == "POST":
        name = request.POST.get("name")
        category_id = request.POST.get("category")
        description = request.POST.get("description")

        # Validate and save the product
        category = Category.objects.get(id=category_id)
        product = Product.objects.create(
            name=name,
            category=category,
            description=description
        )

        # Handle product variants
        for key in request.POST:
            if key.startswith("variant_") and key.endswith("_price"):
                # Extract variant index
                index = key.split("_")[1]

                # Gather data for this variant
                price = request.POST.get(f"variant_{index}_price")
                stock = request.POST.get(f"variant_{index}_stock")
                colors = request.POST.getlist(f"variant_{index}_colors[]")
                color_codes = request.POST.getlist(f"variant_{index}_color_code[]")
                sizes = request.POST.getlist(f"variant_{index}_sizes[]")
                images = request.FILES.getlist(f"variant_{index}_images[]")

                # Create the variant for each color and size combination
                for color_name, color_code in zip(colors, color_codes):
                    # Get or create the color
                    color, created = ProductColor.objects.get_or_create(
                        color_name=color_name
                    )

                    for size_name in sizes:
                        # Get or create the size
                        size, created = ProductSize.objects.get_or_create(size_name=size_name)

                        # Save the variant with color and size
                        variant = ProductVariant.objects.create(
                            product=product,
                            price=price,
                            stock_quantity=stock,
                            color=color,
                            size=size  # Ensure the size is assigned
                        )

                        # Save images for the variant
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
    """
    Allows an admin to cancel any order.
    """
    if not request.user.is_staff:
        messages.error(request, "You do not have the required permissions to cancel orders.")
        return redirect('home')

    order = get_object_or_404(Order, id=order_id)
    if order.status in ['Pending', 'Processing']:
        order.status = 'Cancelled'
        order.save()
        messages.success(request, f"Order #{order.id} has been successfully cancelled.")
    else:
        messages.error(request, "Order cannot be cancelled.")
    return redirect('order_management')  # Redirect to the admin order management page


#####   user products  #####

from django.db.models import Q, Min, Max

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



def product_details(request, product_id, variant_id=None):
    product = get_object_or_404(Product, id=product_id, is_deleted=False)

    # Get the category hierarchy
    categories = []
    current_category = product.category
    while current_category:
        categories.insert(0, current_category)
        current_category = current_category.parent_category

    # Get all variants and select the default
    variants = product.productvariant_set.all()
    selected_variant = get_object_or_404(variants, id=variant_id) if variant_id else variants.first()

    # Fetch active offers
    now = timezone.now()
    product_offer = Offer.objects.filter(
        offer_type='product', product=product, is_active=True,
        start_date__lte=now, end_date__gte=now
    ).first()

    category_offers = Offer.objects.filter(
        offer_type='category', category__in=categories, is_active=True,
        start_date__lte=now, end_date__gte=now
    ).select_related('category')

    category_offer = category_offers.order_by('-discount_value').first() if category_offers.exists() else None

    # Determine the best discount
    best_offer = None
    discount_value = 0
    if product_offer and category_offer:
        best_offer = product_offer if product_offer.discount_value > category_offer.discount_value else category_offer
    elif product_offer:
        best_offer = product_offer
    elif category_offer:
        best_offer = category_offer

    if best_offer:
        if best_offer.discount_type == 'percentage':  # Assuming discount_type is 'percentage' or 'fixed'
            discount_value = selected_variant.price * (best_offer.discount_value / 100)
        else:  # Fixed amount discount
            discount_value = best_offer.discount_value

    # Ensure discount does not make price negative
    discounted_price = max(selected_variant.price - discount_value, 0)

    # Add to cart logic
    if request.method == 'POST':
        variant_id = request.POST.get('variant_id')
        quantity = int(request.POST.get('quantity', 1))
        variant = get_object_or_404(ProductVariant, id=variant_id)
        cart_item, created = Cart.objects.get_or_create(user=request.user, product_variant=variant)
        if cart_item:
            cart_item.quantity += quantity
            cart_item.price = discounted_price
            cart_item.save()
        return redirect('cart')

    # Product rating calculations
    ratings = Rating.objects.filter(product=product)
    total_ratings = ratings.count()
    avg_rating = ratings.aggregate(Avg('rating'))['rating__avg'] if total_ratings else 0
    rounded_avg_rating = round(avg_rating) if avg_rating else 0
    filled_stars_range = range(rounded_avg_rating)
    empty_stars_range = range(5 - rounded_avg_rating)

    # Pagination for reviews
    reviews = Review.objects.filter(product=product)
    paginator = Paginator(reviews.order_by('-created_at'), 5)
    page_number = request.GET.get('page')
    reviews_page = paginator.get_page(page_number)

    for review in reviews_page:
        review.rating_value = Rating.objects.filter(user=review.user, product=product).first().rating \
            if Rating.objects.filter(user=review.user, product=product).exists() else 0

    # Related products
    related_products = Product.objects.filter(category=product.category).exclude(id=product.id)[:4]
    for related_product in related_products:
        ratings = Rating.objects.filter(product=related_product)
        total_ratings = ratings.count()
        related_product.avg_rating = ratings.aggregate(Avg('rating'))['rating__avg'] if total_ratings else 0

    context = {
        'product': product,
        'selected_variant': selected_variant,
        'variants': variants,
        'categories': categories,
        'avg_rating': avg_rating,
        'filled_stars_range': filled_stars_range,
        'empty_stars_range': empty_stars_range,
        'rating_breakdown': [{'rating': i, 'percentage': 20} for i in range(1, 6)],
        'reviews': reviews_page,
        'related_products': related_products,
        'best_offer': best_offer,
        'product_offer': product_offer,
        'category_offer': category_offer,
        'discounted_price': discounted_price,
        'original_price': selected_variant.price
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
    active_tab = request.GET.get('active_tab', 'details')  

    # Handle order cancellation
    if request.method == "POST" and 'cancel_order' in request.POST:
        order_id = request.POST.get('order_id')
        order = get_object_or_404(Order, id=order_id, user=user)

        # Allow cancellation only for orders not yet delivered or already cancelled
        if order.status not in ['Delivered', 'Cancelled', 'Completed']:
            order.status = 'Cancelled'
            order.save()
            success(request, f"Order #{order.id} has been successfully cancelled.")
        else:
            error(request, f"Order #{order.id} cannot be cancelled.")
        return redirect('profile')

    # Prepare detailed order data
    order_details = []
    for order in orders:
        items = []
        for item in order.items.all():  # Use the correct related_name "items"
            # Fetch the first image for the product variant
            image = item.product_variant.productimage_set.first()
            items.append({
                'product_name': item.product_variant.product.name,  # Access product name via product_variant
                'product_image': image.image_url.url if image else None,  # Access image if available
                'color': item.product_variant.color.color_name,  # Access color name
                'size': item.product_variant.size.size_name,  # Access size name
                'quantity': item.quantity,
                'price': item.price,
                'total_price': item.price * item.quantity,
            })
        order_details.append({
            'id': order.id,
            'status': order.status,
            'date': order.order_date,
            'total_amount': order.total_amount,
            'delivery_status': order.status,  # Use status for delivery
            'items': items,
        })

    return render(request, 'user/profile.html', {
        'user': user,
        'addresses': addresses,
        'orders': order_details,
        'active_tab': active_tab,
    })



@never_cache
@login_required
def edit_profile(request):
    if request.method == 'POST':
        # Ensure you use the `request.POST` data to update the user instance
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

@never_cache
@login_required
def user_cancel_order(request, order_id):
    """
    Allows a user to cancel their own orders if they meet the criteria.
    """
    order = get_object_or_404(Order, id=order_id, user=request.user)
    if order.status in ['Pending', 'Processing']:
        order.status = 'Cancelled'
        order.save()
        messages.success(request, f"Order #{order.id} has been successfully cancelled.")
    else:
        messages.error(request, "Order cannot be cancelled.")
    return redirect('profile')  # Redirect to the user's profile




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

#cart
def add_to_cart(request, variant_id):
    variant = get_object_or_404(ProductVariant, id=variant_id)

    # Get or create the user's cart item for this product variant
    cart_item, created = Cart.objects.get_or_create(user=request.user, product_variant=variant)

    if request.method == 'POST':
        quantity = int(request.POST.get('quantity', 1))  # Default to 1 if no quantity is provided
        
        if quantity <= variant.stock_quantity:  # Ensure we do not exceed stock
            cart_item.quantity = quantity
            cart_item.save()
            return redirect('cart_view')  # Redirect to cart view
        else:
            return HttpResponse("Not enough stock.", status=400)

    return redirect('cart_view')  # Redirect if not a POST request

def cart_view(request):
    cart_items = Cart.get_user_cart(request.user)
    cart_data = []

    for item in cart_items:
        variant = item.product_variant
        image = ProductImage.objects.filter(variant=variant).first()
        discounted_price = variant.get_discounted_price()  
        
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

@login_required
def checkout(request):
    user = request.user
    cart_items = Cart.get_user_cart(user)
    total_price = sum(item.get_discounted_total() for item in cart_items)

    cart_data = []
    for item in cart_items:
        image = ProductImage.objects.filter(variant=item.product_variant).first()
        cart_data.append({
            'id': item.id,
            'product_name': item.product_variant.product.name,
            'color': item.product_variant.color.color_name,
            'size': item.product_variant.size.size_name,
            'price': item.product_variant.get_discounted_price(),
            'quantity': item.quantity,
            'total_price': item.get_discounted_total(),
            'image_url': image.image_url.url if image else None,
        })

    discount = 0
    applied_coupon_code = None
    shipping_address = None

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
                    request.session["discount"] = float(discount)
                    applied_coupon_code = coupon_code
                    messages.success(request, f"Coupon applied! Discount: ₹{discount}")
            except Coupon.DoesNotExist:
                messages.error(request, "Invalid coupon code")

        address_select = request.POST.get("address_select")
        if address_select:
            try:
                shipping_address = Address.objects.get(id=address_select, user=user)
                request.session["shipping_address_id"] = shipping_address.id
                messages.success(request, "Shipping address selected successfully.")
            except Address.DoesNotExist:
                messages.error(request, "Invalid address selected.")
        else:
            new_address = Address.create_from_request(request)
            request.session["shipping_address_id"] = new_address.id
            messages.success(request, "New address added and selected successfully.")

    selected_address_id = request.session.get("shipping_address_id")
    if selected_address_id:
        shipping_address = Address.objects.get(id=selected_address_id, user=user)

    return render(request, "user/checkout.html", {
        "cart_items": cart_data,
        "total_price": total_price,
        "discount": discount,
        "applied_coupon": applied_coupon_code,
        "shipping_address": shipping_address,
    })

@login_required
@transaction.atomic
def place_order(request):
    user = request.user
    cart_items = Cart.get_user_cart(user)

    if not cart_items.exists():
        messages.error(request, "Your cart is empty.")
        return redirect("checkout")

    subtotal = sum(item.total_price() for item in cart_items)
    total_discount = request.session.get("discount", 0)
    final_price = subtotal - total_discount
    applied_coupon = request.session.get("applied_coupon")

    if request.method == "POST":
        payment_method = request.POST.get("payment_method", "cod")
        shipping_address = get_object_or_404(Address, id=request.session.get("shipping_address_id"))

        order = Order.objects.create(
            user=user,
            shipping_address=shipping_address,
            subtotal=subtotal,
            discount=total_discount,
            total_amount=final_price,
            applied_coupon=applied_coupon,
            status="Pending" if payment_method == "cod" else "Processing",
        )

        for cart_item in cart_items:
            variant = cart_item.product_variant
            discounted_price = cart_item.product_variant.get_discounted_price()

            OrderItem.objects.create(
                order=order,
                product_variant=variant,
                quantity=cart_item.quantity,
                price=discounted_price,  # Save the discounted price
            )

            variant.stock_quantity -= cart_item.quantity
            variant.save()

        cart_items.delete()
        for key in ["applied_coupon", "discount"]:
            request.session.pop(key, None)

        messages.success(request, "Order placed successfully!")
        return redirect("order_summary", order_id=order.id)

    return render(request, "user/place_order.html", {
        "cart_items": cart_items,
        "subtotal": subtotal,
        "total_discount": total_discount,
        "final_price": final_price,
    })



@login_required
def order_summary(request, order_id):
    order = get_object_or_404(Order, id=order_id)
    order_items = order.items.all().select_related('product_variant').prefetch_related('product_variant__productimage_set')

    order_data = []
    for item in order_items:
        image = item.product_variant.productimage_set.first()
        original_price = item.product_variant.price  # Original price
        discounted_price = item.price  # Discounted price stored in OrderItem
        total_price = discounted_price * item.quantity
        total_savings = (original_price - discounted_price) * item.quantity  # Savings per item
        
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




@login_required
def cancel_order(request, order_id):
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if order.status in ["Pending", "Processing"]:  # Check if order is cancellable
        order.status = "Cancelled"
        order.save()
        messages.success(request, "Your order has been cancelled.")
    else:
        messages.error(request, "This order cannot be cancelled.")

    return redirect("profile")



# -------------- OFFER MANAGEMENT -------------- #

@require_http_methods(["GET"])
def offer_list(request):
    """
    Render the offer list page.
    """
    return render(request, "admin/orders/offer_list.html")

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
            "discount": offer.discount,
            "valid": offer.is_active,
            "product": offer.product.name if offer.product else None,
            "category": offer.category.category_name if offer.category else None,
            "min_purchase": offer.min_purchase,
            "start_date": offer.start_date.strftime("%Y-%m-%d %H:%M"),
            "end_date": offer.end_date.strftime("%Y-%m-%d %H:%M"),
        }
        offer_list.append(offer_data)

    return JsonResponse(offer_list, safe=False)

@require_http_methods(["GET"])
def get_referral_offers(request):
    """
    API endpoint to fetch all referral offers.
    """
    referral_offers = ReferralOffer.objects.all().order_by("-id")
    referral_list = []

    for referral in referral_offers:
        referral_data = {
            "id": referral.id,
            "referrer": referral.referrer.username,
            "referred_user": referral.referred_user.username,
            "reward_amount": referral.reward_amount,
            "is_claimed": referral.is_claimed,
        }
        referral_list.append(referral_data)

    return JsonResponse(referral_list, safe=False)

@require_http_methods(["DELETE"])
def delete_offer(request, offer_id):
    """
    API endpoint to delete an offer (both regular and referral offers).
    """
    try:
        offer = get_object_or_404(Offer, id=offer_id)
        offer.delete()
        return JsonResponse({"message": "Offer deleted successfully!"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
    
@require_http_methods(["GET", "POST"])
def create_offer(request):
    if request.method == "GET":
        products = Product.objects.all()
        categories = Category.objects.all().exclude(is_deleted=True)
        users = CustomUser.objects.all()
        return render(request, "admin/orders/create_offer.html", {"products": products, "categories": categories, "users": users})

    elif request.method == "POST":
        try:
            data = request.POST
            print("Received data:", data)  # Debugging line

            offer_type = data.get("offer_type")
            discount = float(data.get("discount") or 0)
            min_purchase = float(data.get("min_purchase") or 0)

            # ✅ Fix: Use default dates if missing
            start_date_str = data.get("start_date")
            end_date_str = data.get("end_date")

            if start_date_str:
                start_date = timezone.datetime.fromisoformat(start_date_str)
            else:
                start_date = timezone.now()  # Use current time if missing ✅

            if end_date_str:
                end_date = timezone.datetime.fromisoformat(end_date_str)
            else:
                end_date = start_date + timezone.timedelta(days=30)  # Default to 30 days later ✅

            is_active = data.get("is_active", "true").lower() == "true"

            product = get_object_or_404(Product, id=data["product_id"]) if data.get("product_id") else None
            category = get_object_or_404(Category, id=data["category_id"]) if data.get("category_id") else None

            offer = Offer.objects.create(
                offer_type=offer_type,
                discount=discount,
                product=product,
                category=category,
                min_purchase=min_purchase,
                start_date=start_date,
                end_date=end_date,
                is_active=is_active,
            )

            if offer_type == "referral":
                referrer = get_object_or_404(CustomUser, id=data.get("referrer_id"))
                referred_user = get_object_or_404(CustomUser, id=data.get("referred_user_id"))
                
                reward_amount = float(data.get("reward_amount") or 0)

                referral_offer = ReferralOffer.objects.create(
                    offer=offer,
                    referrer=referrer,
                    referred_user=referred_user,
                    reward_amount=reward_amount,
                )
                
                referrer_wallet, _ = Wallet.objects.get_or_create(user=referrer)
                referrer_wallet.credit(reward_amount, reason="Referral Reward")

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


def coupon_list(request):
    page_number = request.GET.get('page', 1)  # Get the current page from the query parameters
    items_per_page = 10  # Define how many coupons to show per page (adjust as needed)
    search_query = request.GET.get('search', '')  # Get the search query from the request
    
    # Filter coupons based on the search query
    coupons = Coupon.objects.filter(is_active=True, expiration_date__gte=timezone.now())
    if search_query:
        coupons = coupons.filter(coupon_code__icontains=search_query)  # Filter by coupon code
        # You can add more filters here (e.g., by discount_value or expiration_date)

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

def add_coupon(request):
    if request.method == 'POST':
        coupon_code = request.POST.get('coupon_code')
        discount_type = request.POST.get('discount_type')  # Ensure this is being sent
        discount_value = request.POST.get('discount_value')
        max_discount = request.POST.get('max_discount')
        min_purchase = request.POST.get('min_purchase')
        usage_limit = request.POST.get('usage_limit')
        per_user_limit = request.POST.get('per_user_limit')
        expiration_date = request.POST.get('expiration_date')
        allowed_categories = request.POST.getlist('allowed_categories')  # Multiple categories selected
        allowed_users = request.POST.getlist('allowed_users')  # Multiple users selected

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

    categories = Category.objects.all()  # Assuming Category is a model in your app
    users = CustomUser.objects.all()  # Assuming CustomUser is the user model
    return render(request, 'admin/orders/add_coupon.html', {'categories': categories, 'users': users})


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
        order_total = float(data.get("order_total", 0))

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

        if order_total < coupon.min_purchase:
            return JsonResponse({"error": f"Minimum purchase of ₹{coupon.min_purchase} required"}, status=400)

        # Calculate actual discount
        if coupon.discount_type == "fixed":
            discount = min(coupon.discount_value, order_total)
        elif coupon.discount_type == "percentage":
            discount = (coupon.discount_value / 100) * order_total
            if coupon.max_discount:
                discount = min(discount, coupon.max_discount)

        return JsonResponse({
            "message": "Coupon valid",
            "discount": discount,
            "coupon_code": coupon_code
        })

    except Coupon.DoesNotExist:
        return JsonResponse({"error": "Invalid coupon"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

import datetime
import pandas as pd
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from reportlab.pdfgen import canvas

def sales_report(request):
    """Handles sales report filtering and downloading."""
    filter_type = request.GET.get('filter', 'daily')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    # Ensure timezone awareness
    today = timezone.now().date()

    if filter_type == "daily":
        start_date = end_date = today
    elif filter_type == "weekly":
        start_date = today - datetime.timedelta(days=7)
        end_date = today
    elif filter_type == "monthly":
        start_date = today.replace(day=1)
        end_date = today
    elif filter_type == "custom" and start_date and end_date:
        start_date = datetime.datetime.strptime(start_date, "%Y-%m-%d").date()
        end_date = datetime.datetime.strptime(end_date, "%Y-%m-%d").date()
    else:
        start_date = end_date = today

    # Filter orders based on date range
    orders = Order.objects.filter(order_date__date__range=[start_date, end_date])

    # Aggregated values
    total_orders = orders.count()
    total_sales = orders.aggregate(Sum('total_amount'))['total_amount__sum'] or 0
    total_discount = orders.aggregate(Sum('discount'))['discount__sum'] or 0

    context = {
        'orders': orders,
        'total_orders': total_orders,
        'total_sales': total_sales,
        'total_discount': total_discount,
        'filter_type': filter_type,
        'start_date': start_date,
        'end_date': end_date
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
        elif filter_type == "custom" and start_date and end_date:
            # 🔹 Use dateutil.parser to handle different date formats
            start_date = parser.parse(start_date).date()
            end_date = parser.parse(end_date).date()
        else:
            start_date = end_date = today
    except ValueError:
        return JsonResponse({"error": "Invalid date format"}, status=400)

    # Filter orders based on date range
    orders = Order.objects.filter(order_date__date__range=[start_date, end_date])

    # PDF Export
    if report_type == "pdf":
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="sales_report.pdf"'
        pdf = canvas.Canvas(response)
        pdf.drawString(100, 800, f"Sales Report ({start_date} to {end_date})")
        y_position = 780

        for order in orders:
            y_position -= 20
            pdf.drawString(100, y_position, f"Order ID: {order.id}, Amount: ${order.total_amount}, Discount: ${order.discount}")

        pdf.showPage()
        pdf.save()
        return response

    # Excel Export
    elif report_type == "excel":
        if orders.exists():
            df = pd.DataFrame(list(orders.values("id", "order_date", "total_amount", "discount")))
        else:
            df = pd.DataFrame(columns=["ID", "Order Date", "Total Amount", "Discount"])  # Handle empty data

        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename="sales_report.xlsx"'
        df.to_excel(response, index=False)
        return response

    return JsonResponse({"error": "Invalid report type"}, status=400)
