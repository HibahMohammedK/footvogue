from django.shortcuts import render, redirect, get_object_or_404
from .models import *
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout
from django.http import JsonResponse
from django.utils.timezone import now
from .utils import send_sms
import phonenumbers
from phonenumbers import NumberParseException
from django.contrib.auth.decorators import user_passes_test
import logging
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required

from django.db.models import Prefetch

def product_details(request, product_id):
    # Fetch the product and its category
    product = get_object_or_404(Product, id=product_id, is_deleted=False)

    # Get the category and its parent categories (if any)
    categories = []
    current_category = product.category
    while current_category:
        categories.insert(0, current_category)  # Insert at the beginning to maintain the correct order
        current_category = current_category.parent_category  # Move to the parent category

    # Get all variants for the product
    variants = product.productvariant_set.all()  # Assuming ProductVariant is related via a ForeignKey to Product

    # Pass product, variants, and categories to context
    context = {
        'product': product,
        'variants': variants,
        'categories': categories,
    }
    return render(request, 'user/product_details.html', context)







def home(request):
    # Fetch products from the database
    products = Product.objects.prefetch_related(
        'productvariant_set__productimage_set'
    ).filter(is_deleted=False)  # Adjust filters based on your requirements

    # Create a rating range (1 to 5) for use in the template
    rating_range = range(1, 6)

    # Render the home template with products and rating range
    return render(request, 'user/home.html', {'products': products, 'rating_range': rating_range})

# Register View
def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username").strip()
        email = request.POST.get("email").strip()
        password = request.POST.get("password").strip()
        confirm_password = request.POST.get("confirm_password").strip()
        phone_number = request.POST.get("phone_number").strip()

        if not username or not email or not password or not phone_number:
            messages.error(request, "All fields are required.")
            return redirect("register")

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("register")

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("register")

        if CustomUser.objects.filter(phone_number=phone_number).exists():
            messages.error(request, "Phone number already registered.")
            return redirect("register")

        try:
            formatted_number = phonenumbers.format_number(
                phonenumbers.parse(phone_number, None),
                phonenumbers.PhoneNumberFormat.E164
            )
        except NumberParseException:
            messages.error(request, "Invalid phone number format.")
            return redirect("register")

        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password,
            phone_number=formatted_number
        )
        user.save()

        messages.success(request, "Registration successful! Please log in.")
        return redirect("login")

    return render(request, "user/register.html")

# Logout View
def logout_view(request):
    logout(request)
    return redirect('home')

def login_view(request):
    if request.method == 'POST':
        login_identifier = request.POST.get('login_identifier')
        password = request.POST.get('password', None)
        otp = request.POST.get('otp', None)
        is_otp_login = request.POST.get('is_otp_login')  # This flag determines if OTP login is being used
        
        try:
            if is_otp_login:
                # Handle OTP login
                phone_number = login_identifier
                try:
                    # Validate and format phone number
                    parsed_number = phonenumbers.parse(phone_number, None)
                    formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                except NumberParseException:
                    messages.error(request, 'Invalid phone number format. Please include the country code.')
                    return redirect('login')

                user_instance = CustomUser.objects.filter(phone_number=formatted_number).first()
                if user_instance:
                    otp_instance = OTP.objects.filter(user=user_instance, phone_number=formatted_number).first()
                    if otp_instance and not otp_instance.is_expired() and otp_instance.otp == otp:
                        otp_instance.is_verified = True
                        otp_instance.save()
                        auth_login(request, user_instance)
                        messages.success(request, 'Logged in successfully via OTP!')
                        if user_instance.is_superuser:  # Check if the user is an admin
                            return redirect('admin_dash')  # Redirect to admin dashboard
                        return redirect('home')
                    else:
                        messages.error(request, 'Invalid or expired OTP.')
                else:
                    messages.error(request, 'No user found with this phone number.')
            else:
                # Handle traditional login (username/email + password)
                user_instance = None
                if '@' in login_identifier and '.' in login_identifier:
                    user_instance = CustomUser.objects.filter(email=login_identifier).first()
                else:
                    user_instance = CustomUser.objects.filter(username=login_identifier).first()

                if user_instance:
                    user = authenticate(request, username=user_instance.username, password=password)
                    if user:
                        auth_login(request, user)
                        messages.success(request, 'Logged in successfully!')
                        if user.is_superuser:  # Check if the user is an admin
                            return redirect('admin_dash')  # Redirect to admin dashboard
                        return redirect('home')
                    else:
                        messages.error(request, 'Invalid credentials.')
                else:
                    messages.error(request, 'No user found with the provided identifier.')
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")

    return render(request, 'login.html')


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def send_otp(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            phone_number = data.get("phone_number")
            if not phone_number:
                return JsonResponse({"success": False, "error": "Phone number is required"})

            # Simulate OTP generation and sending
            otp = "1234"  # Replace with actual OTP generation logic
            print(f"Sending OTP {otp} to {phone_number}")  # Debug: Log OTP
            
            return JsonResponse({"success": True})
        except Exception as e:
            return JsonResponse({"success": False, "error": str(e)})
    return JsonResponse({"success": False, "error": "Invalid request"})

# from twilio.rest import Client
# from django.conf import settings
# from django.http import JsonResponse

# def send_otp(request):
#     phone_number = request.POST.get('phone_number')
#     otp = OTP.generate_otp()  # Use a function to generate the OTP
    
#     # Create a Twilio client
#     client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    
#     try:
#         message = client.messages.create(
#             body=f"Your OTP is {otp}",
#             from_=settings.TWILIO_PHONE_NUMBER,  # Twilio number
#             to=phone_number
#         )
#         return JsonResponse({'success': True})
#     except Exception as e:
#         return JsonResponse({'success': False, 'error': str(e)})

def verify_otp(request):
    """Verify OTP entered by the user"""
    if request.method == 'POST':
        phone_number = request.POST.get('phone_number')
        otp = request.POST.get('otp')
        otp_instance = OTP.objects.filter(phone_number=phone_number, otp=otp).first()
        if otp_instance and not otp_instance.is_expired() and not otp_instance.is_verified:
            otp_instance.is_verified = True
            otp_instance.save()
            return JsonResponse({'success': True, 'message': 'OTP verified successfully.'})
        else:
            return JsonResponse({'success': False, 'message': 'Invalid or expired OTP.'})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})




### admin view ###

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

# Admin Dashboard Home
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


# Block User
@login_required
def block_user(request, user_id):
    if not request.user.is_superuser:
        return redirect('login')  # Ensure only admin can access

    user = get_object_or_404(CustomUser, id=user_id)
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

    categories = Category.objects.all()
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
    # Retrieve the product object
    product = get_object_or_404(Product, pk=pk)
    
    # Soft delete the product by setting `is_deleted = True`
    product.is_deleted = True
    product.save()
    
    # Add a success message
    messages.success(request, "Product deleted successfully!")
    
    # Redirect to the product list (or another view as needed)
    return redirect('view_products')


#####   user products  #####




