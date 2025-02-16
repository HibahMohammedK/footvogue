import random
import string
from django.core.mail import send_mail
import razorpay
from django.conf import settings

def generate_and_send_otp(user):
    # Generate a random 6-digit OTP
    otp_code = ''.join(random.choices(string.digits, k=6))

    # Save OTP in the database
    from .models import OTP
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