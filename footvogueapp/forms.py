# forms.py

from django import forms
from .models import Category, Product, ProductVariant, ProductImage,Review, Rating
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

# class ProductForm(forms.ModelForm):
#     class Meta:
#         model = Product
#         fields = ['name', 'category', 'description']

    
#     def clean_category(self):
#         category = self.cleaned_data.get('category')  # Get the category object
#         if not Category.objects.filter(id=category.id).exists():
#             raise forms.ValidationError(f"Selected category does not exist.")
#         return category  # Return the category object directly

# class ProductVariantForm(forms.ModelForm):
#     class Meta:
#         model = ProductVariant
#         fields = ['color', 'size', 'price', 'stock_quantity']

# class ProductImageForm(forms.ModelForm):
#     class Meta:
#         model = ProductImage
#         fields = ['variant', 'image_url']

# # Formsets for handling multiple variants and images
# ProductVariantFormSet = modelformset_factory(ProductVariant, form=ProductVariantForm, extra=1)
# ProductImageFormSet = modelformset_factory(ProductImage, form=ProductImageForm, extra=1)

