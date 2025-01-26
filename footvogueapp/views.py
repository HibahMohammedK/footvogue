from django.shortcuts import render, redirect, get_object_or_404
from .models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout
from django.views.decorators.cache import never_cache
import logging
from django.contrib.auth.decorators import login_required
from .forms import ReviewForm, RatingForm
from django.core.paginator import Paginator
from django.db.models import Avg, Count
from .utils import generate_and_send_otp 
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.urls import reverse
from django.http import HttpResponse
from django.db import transaction
from django.contrib.messages import success, error


   

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
    # Extract filter parameters from the GET request
    category_filter = request.GET.get('category', None)
    price_min = request.GET.get('price_min', None)
    price_max = request.GET.get('price_max', None)
    sort_criteria = request.GET.get('sort', 'new_arrivals')  # Default sorting
    in_stock = request.GET.get('in_stock', None)

    # Initialize the filter query
    filter_query = Q()

    # Category filter
    if category_filter:
        filter_query &= Q(product__category__id=category_filter)

    # Price filter (on ProductVariant)
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

    # Apply the filters to the ProductVariant model
    product_variants = ProductVariant.objects.filter(price_filter_query)

    # Get distinct products by filtering on the ProductVariant model
    product_ids = product_variants.values('product_id').distinct()
    products = Product.objects.filter(id__in=product_ids)

    # Sorting logic based on the selected criteria
    if sort_criteria == 'popularity':
        # Order by average rating from Rating table
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

    # Apply distinct again to remove duplicate products
    products = products.distinct()

    # Fetch categories again for filter sidebar
    categories = Category.objects.all().exclude(is_deleted= True)

    # Render the product list
    return render(request, 'user/products.html', {
        'products': products,
        'categories': categories,
        'selected_categories': category_filter,
        'sort_criteria': sort_criteria,
        'show_in_stock_only': in_stock == 'true',
        'price_min': price_min,
        'price_max': price_max
    })


def product_details(request, product_id, variant_id=None):
    # Fetch the product and ensure it's not deleted
    product = get_object_or_404(Product, id=product_id, is_deleted=False)

    # Get the category and its parent categories (if any)
    categories = []
    current_category = product.category
    while current_category:
        categories.insert(0, current_category)  # Insert at the beginning to maintain the correct order
        current_category = current_category.parent_category  # Move to the parent category

    # Get all variants for the product
    variants = product.productvariant_set.all()  # Assuming ProductVariant is related via a ForeignKey to Product

    # If a variant_id is provided, use that; otherwise, default to the first variant
    selected_variant = get_object_or_404(product.productvariant_set, id=variant_id) if variant_id else variants.first()


     # Handle adding to cart (POST request)
    if request.method == 'POST':
        # Get the variant_id and quantity from the form
        variant_id = request.POST.get('variant_id')
        quantity = int(request.POST.get('quantity', 1))  # Default to 1 if no quantity is provided
        
        # Get the selected variant and add it to the cart
        variant = get_object_or_404(ProductVariant, id=variant_id)

        # Create or update the Cart item for the user
        cart_item, created = Cart.objects.get_or_create(user=request.user, product_variant=variant)
        if cart_item:
            cart_item.quantity += quantity  # Increase the quantity
            cart_item.save()
        
        return redirect('cart')  # Redirect to the cart view after adding the item

    # Calculate the average rating from the Rating model
    ratings = Rating.objects.filter(product=product)
    total_ratings = ratings.count()
    avg_rating = ratings.aggregate(Avg('rating'))['rating__avg'] if total_ratings else 0
    rounded_avg_rating = round(avg_rating) if avg_rating else 0  # Round to the nearest integer

    # Prepare the star ranges
    filled_stars_range = range(rounded_avg_rating)  # Range for filled stars
    empty_stars_range = range(5 - rounded_avg_rating)  # Range for empty stars

    # Pagination for reviews (optional, show 5 reviews per page)
    reviews = Review.objects.filter(product=product)
    paginator = Paginator(reviews.order_by('-created_at'), 5)  # Order by creation date, latest first
    page_number = request.GET.get('page')
    reviews_page = paginator.get_page(page_number)

    # Attach the rating for each review to the review object
    for review in reviews_page:
        review.rating_value = Rating.objects.filter(user=review.user, product=product).first().rating if Rating.objects.filter(user=review.user, product=product).exists() else 0

    # Get related products
    related_products = Product.objects.filter(category=product.category).exclude(id=product.id)[:4]  # Adjust the number of related products as needed

    # Calculate avg_rating for related products
    for related_product in related_products:
        ratings = Rating.objects.filter(product=related_product)
        total_ratings = ratings.count()
        related_product.avg_rating = ratings.aggregate(Avg('rating'))['rating__avg'] if total_ratings else 0

    # Pass the necessary values to the template
    context = {
        'product': product,
        'selected_variant': selected_variant,
        'variants': variants,
        'categories': categories,
        'avg_rating': avg_rating,
        'filled_stars_range': filled_stars_range,
        'empty_stars_range': empty_stars_range,
        'rating_breakdown': [{'rating': i, 'percentage': 20} for i in range(1, 6)],  # Placeholder data
        'reviews': reviews_page,  # Paginated reviews
        'related_products': related_products  # Pass related products with avg_rating
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
        image = ProductImage.objects.filter(variant=item.product_variant).first()
        cart_data.append({
            'id': item.id,
            'product_name': item.product_variant.product.name,
            'color': item.product_variant.color.color_name,
            'size': item.product_variant.size.size_name,
            'price': item.product_variant.price,
            'quantity': item.quantity,
            'total_price': item.total_price(),
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
    total_price = sum(item.total_price() for item in cart_items)

    # Prepare cart data including product image URLs
    cart_data = []
    for item in cart_items:
        image = ProductImage.objects.filter(variant=item.product_variant).first()
        cart_data.append({
            'id': item.id,
            'product_name': item.product_variant.product.name,
            'color': item.product_variant.color.color_name,
            'size': item.product_variant.size.size_name,
            'price': item.product_variant.price,
            'quantity': item.quantity,
            'total_price': item.total_price(),
            'image_url': image.image_url.url if image else None,
        })

    if request.method == "POST":
        use_default = request.POST.get("use_default") == "true"

        if use_default:
            # Fetch the default address
            shipping_address = Address.objects.filter(user=user, is_default=True).first()
            if not shipping_address:
                messages.error(request, "No default address found. Please provide an address.")
                return redirect("checkout")

            # If a default address exists, update it with new details
            shipping_address.address_line1 = request.POST.get("address_line1", "").strip()
            shipping_address.city = request.POST.get("city", "").strip()
            shipping_address.state = request.POST.get("state", "").strip()
            shipping_address.postal_code = request.POST.get("postal_code", "").strip()
            shipping_address.country = request.POST.get("country", "").strip()

            # Check if all required fields are provided
            if not all([shipping_address.address_line1, shipping_address.city, shipping_address.state, shipping_address.postal_code, shipping_address.country]):
                messages.error(request, "Please fill out all required address fields.")
                return redirect("checkout")

            shipping_address.save()  # Save the updated address
            messages.success(request, "Address updated successfully.")

        else:
            # Collect new address details from POST data
            address_line1 = request.POST.get("address_line1", "").strip()
            city = request.POST.get("city", "").strip()
            state = request.POST.get("state", "").strip()
            postal_code = request.POST.get("postal_code", "").strip()
            country = request.POST.get("country", "").strip()

            # Check if all required fields are provided
            if not all([address_line1, city, state, postal_code, country]):
                messages.error(request, "Please fill out all required address fields.")
                return redirect("checkout")

            # Save the new address
            shipping_address = Address.objects.create(
                user=user,
                address_line1=address_line1,
                address_line2=request.POST.get("address_line2", "").strip(),
                city=city,
                state=state,
                postal_code=postal_code,
                country=country,
                is_default=False,  # Do not save as default unless explicitly set
            )
            messages.success(request, "Address saved successfully.")

        # Save the shipping address in session for order placement
        request.session["shipping_address_id"] = shipping_address.id

        return redirect("checkout")  # Proceed to confirm order page

    return render(request, "user/checkout.html", {
        "cart_items": cart_data,
        "total_price": total_price,
    })





@login_required
@transaction.atomic
def place_order(request):
    user = request.user
    cart_items = Cart.get_user_cart(user)

    if not cart_items.exists():
        messages.error(request, "Your cart is empty.")
        return redirect("checkout")

    shipping_address_id = request.session.get("shipping_address_id")
    if not shipping_address_id:
        messages.error(request, "No shipping address selected. Please go back to checkout.")
        return redirect("checkout")

    try:
        shipping_address = Address.objects.get(id=shipping_address_id)
    except Address.DoesNotExist:
        messages.error(request, "The selected address is no longer available.")
        return redirect("checkout")

    total_price = sum(item.total_price() for item in cart_items)

    if request.method == "POST":
        # Handle custom shipping address if selected
        if request.POST.get("shipping_address"):
            shipping_first_name = request.POST.get("shipping_first_name")
            shipping_last_name = request.POST.get("shipping_last_name")
            shipping_email = request.POST.get("shipping_email")
            shipping_address_line1 = request.POST.get("shipping_address")
            shipping_city = request.POST.get("shipping_city")
            shipping_state = request.POST.get("shipping_state")
            shipping_postal_code = request.POST.get("shipping_postal_code")
            shipping_country = request.POST.get("shipping_country")
            # You could implement validation and saving here for new shipping address

        # Get payment method
        payment_method = request.POST.get("payment_method")
        if not payment_method:
            messages.error(request, "Please select a payment method.")
            return redirect("place_order")

        if payment_method not in ["cod", "bank_transfer", "cheque", "paypal"]:
            messages.error(request, "Invalid payment method.")
            return redirect("place_order")

        # Create order
        order = Order.objects.create(
            user=user,
            shipping_address=shipping_address,
            total_amount=total_price,
            status="Pending" if payment_method == "cod" else "Processing",
        )

        # Create order items and adjust stock
        for cart_item in cart_items:
            # Ensure the product_variant is passed when creating OrderItem
            OrderItem.objects.create(
                order=order,
                product_variant=cart_item.product_variant,  # This fixes the IntegrityError
                quantity=cart_item.quantity,
                price=cart_item.product_variant.price * cart_item.quantity,  # Total price for the item
            )
            # Update stock quantity
            cart_item.product_variant.stock_quantity -= cart_item.quantity
            cart_item.product_variant.save()

        # Clear the user's cart
        cart_items.delete()

        # Set success message
        if payment_method == "cod":
            messages.success(request, "Order placed successfully! Payment will be collected upon delivery.")
        else:
            messages.success(request, "Order placed successfully!")

        return redirect("order_summary", order_id=order.id)

    return render(request, "user/place_order.html", {
        "cart_items": cart_items,
        "shipping_address": shipping_address,
        "total_price": total_price,
    })

@login_required
def order_summary(request, order_id):
    order = get_object_or_404(Order, id=order_id)

    # Fetch order items, prefetching related ProductVariant and associated ProductImages
    order_items = order.items.all().select_related('product_variant').prefetch_related('product_variant__productimage_set')

    # Prepare order data with image URLs
    order_data = []
    for item in order_items:
        # Get the first product image for the product variant
        image = item.product_variant.productimage_set.first()  # Correctly access related images
        order_data.append({
            'product_name': item.product_variant.product.name,
            'color': item.product_variant.color.color_name,
            'size': item.product_variant.size.size_name,
            'price': item.price,
            'quantity': item.quantity,
            'total_price': item.price * item.quantity,
            'image_url': image.image_url.url if image else None,  # Access the image URL or fallback to None
        })

    return render(request, "user/order_summary.html", {
        "order": order,
        "order_items": order_data,
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

