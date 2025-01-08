from django.urls import path
from . import views



urlpatterns = [
    path('',views.home, name='home'),
    path('login/',views.login_view, name='login'),
    path('register/',views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('email-verification/', views.email_verification_view, name='email_verification'),
 
    # URLs for product details and variant details
    path('product/<int:product_id>/', views.product_details, name='product_details'),
    path('product/<int:product_id>/variant/<int:variant_id>/', views.product_details, name='product_details_variant'),
    path('product/<int:product_id>/submit_review_and_rating/', views.submit_review_and_rating, name='submit_review_and_rating'),

    
    
    ### admin urls ####

    path('admin_dash/', views.admin_dash, name='admin_dash'),
    path('user_management/', views.user_management, name='user_management'),
    path('block_user/<int:user_id>/', views.block_user, name='block_user'),
    path('unblock_user/<int:user_id>/', views.unblock_user, name='unblock_user'),
    
    path('categories/', views.category_list, name='category_list'),
    path('categories/add/', views.add_category, name='add_category'),
    path('categories/edit/<int:category_id>/', views.edit_category, name='edit_category'),
    path('categories/delete/<int:category_id>/', views.delete_category, name='delete_category'),

    path('view-products/', views.view_products, name='view_products'),
    path('products/add/', views.add_product, name='add_product'),
    path('products/edit/<int:pk>/', views.edit_product, name='edit_product'),
    path('products/delete/<int:pk>/', views.delete_product, name='delete_product'),





] 
 