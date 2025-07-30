# footvogueapp/context_processors.py

from .models import Wishlist, Cart, Category

def wishlist_count(request):
    if request.user.is_authenticated:
        count = Wishlist.objects.filter(user=request.user).count()
    else:
        count = 0
    return {'wishlist_count': count}

def cart_count(request):
    if request.user.is_authenticated:
        count = Cart.objects.filter(user=request.user).count()
    else:
        count = 0
    return {'cart_count': count}

def navbar_categories(request):
    return {
        'navbar_categories': Category.objects.filter(parent_category__isnull=True, is_deleted=False)
    }

