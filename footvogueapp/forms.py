# forms.py

from django import forms
from .models import Category,Review,Rating,CustomUser, Address
from django.forms import modelformset_factory

class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ['category_name', 'parent_category']  # Update fields to match the model

class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ['review_text']
        widgets = {
            'review_text': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Write your review...'}),
        }

class RatingForm(forms.ModelForm):
    class Meta:
        model = Rating
        fields = ['rating']
        widgets = {
            'rating': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 5}),
        }


class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['name', 'phone_number', 'email']

class AddressForm(forms.ModelForm):
    class Meta:
        model = Address
        fields = ['address_line1', 'address_line2', 'city', 'state', 'postal_code', 'country', 'is_default']


