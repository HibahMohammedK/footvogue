from django import forms
from .models import Category, Review, Rating, CustomUser, Address


class CategoryForm(forms.ModelForm):
    """Form for managing product categories."""
    
    class Meta:
        model = Category
        fields = ['category_name', 'parent_category']


class ReviewForm(forms.ModelForm):
    """Form for submitting product reviews."""
    
    class Meta:
        model = Review
        fields = ['review_text']
        widgets = {
            'review_text': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Write your review...'}),
        }


class RatingForm(forms.ModelForm):
    """Form for submitting product ratings."""
    
    class Meta:
        model = Rating
        fields = ['rating']
        widgets = {
            'rating': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 5}),
        }


class UserUpdateForm(forms.ModelForm):
    """Form for updating user details."""
    
    class Meta:
        model = CustomUser
        fields = ['name', 'phone_number', 'email']


class AddressForm(forms.ModelForm):
    """Form for managing user addresses."""
    
    class Meta:
        model = Address
        fields = [
            'address_line1', 'address_line2', 'city', 
            'state', 'postal_code', 'country', 'is_default'
        ]
