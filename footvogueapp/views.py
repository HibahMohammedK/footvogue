from django.shortcuts import render, redirect
from .models import CustomUser, OTP
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login, logout
from django.http import JsonResponse
from django.utils.timezone import now
from .utils import send_sms
import phonenumbers
from phonenumbers import NumberParseException
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test

# Home Page
def home(request):
    return render(request, 'user/home.html')

# def login_view(request):
#     if request.method == 'POST':
#         login_identifier = request.POST.get('login_identifier')
#         password = request.POST.get('password', None)
#         otp = request.POST.get('otp', None)
#         is_otp_login = request.POST.get('is_otp_login')

#         try:
#             if is_otp_login:
#                 # Handle OTP login (you may keep this part as it is if you're using OTP login)
#                 pass  # We'll focus on username/email and password login for now.
#             else:
#                 # Handle traditional login using username or email
#                 user_instance = None
#                 if '@' in login_identifier and '.' in login_identifier:
#                     # If it's an email
#                     user_instance = CustomUser.objects.filter(email=login_identifier).first()
#                 else:
#                     # If it's a username
#                     user_instance = CustomUser.objects.filter(username=login_identifier).first()

#                 if user_instance:
#                     # Try to authenticate the user with username and password
#                     user = authenticate(request, username=user_instance.username, password=password)
#                     if user:
#                         auth_login(request, user)  # Log in the user
#                         messages.success(request, 'Logged in successfully!')
#                         return redirect('home')  # Redirect to the home page after login
#                     else:
#                         messages.error(request, 'Invalid password or account disabled.')
#                 else:
#                     messages.error(request, 'No user found with the provided username/email.')

#         except Exception as e:
#             messages.error(request, f"Error: {str(e)}")

#     return render(request, 'login.html')

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
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from django.shortcuts import render, redirect
from .models import CustomUser, OTP  # Assuming CustomUser model for users and OTP model

import phonenumbers
from phonenumbers import NumberParseException
from django.http import JsonResponse

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

def admin_dash(request):
    return render(request,'admin/admin_dash.html')

# Helper function to check if user is admin
def is_admin(user):
    return user.is_authenticated and user.is_staff

# Admin Dashboard
@user_passes_test(is_admin)
def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')

# User Management
@user_passes_test(is_admin)
def admin_user_management(request):
    users = CustomUser.objects.all()
    return render(request, 'admin_user_management.html', {'users': users})

# Block User
@user_passes_test(is_admin)
def block_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.is_blocked = True
    user.save()
    return redirect('admin_users')

# Unblock User
@user_passes_test(is_admin)
def unblock_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    user.is_blocked = False
    user.save()
    return redirect('admin_users')