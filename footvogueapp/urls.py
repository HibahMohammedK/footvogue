from django.urls import path
from . import views
from django.contrib.auth import views as auth_views



urlpatterns = [
    path('',views.home, name='home'),
    path('login/',views.login_view, name='login'),
    path('register/',views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('email-verification/', views.email_verification_view, name='email_verification'),
    path('resend-otp/', views.resend_otp, name='resend_otp'),
 
    # URLs for product details and variant details
    path('products/', views.products, name='products'),
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

    path('order_management/', views.order_management, name='order_management'),
    path('order/<int:order_id>/change_status/', views.change_order_status, name='change_order_status'), 
    path('admin_cancel_order/<int:order_id>/', views.admin_cancel_order, name='admin_cancel_order'),
    
    path('profile/', views.profile, name='profile'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('profile/address/', views.manage_address, name='manage_address'),
    path('profile/order/cancel/<int:order_id>/', views.user_cancel_order, name='user_cancel_order'),
    path('profile/password/', views.change_password, name='change_password'),
    path('address/edit/<int:id>/', views.edit_address, name='edit_address'),
    path('address/delete/<int:id>/', views.delete_address, name='delete_address'),

    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='registration/password_reset_form.html'), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='registration/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='registration/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='registration/password_reset_complete.html'), name='password_reset_complete'),
    
    path('add_to_cart/<int:variant_id>/', views.add_to_cart, name='add_to_cart'),
    path('cart/', views.cart_view, name='cart_view'),
    path('cart/update/<int:cart_item_id>/', views.update_cart, name='update_cart'),
    path('cart/remove/<int:cart_item_id>/', views.remove_from_cart, name='remove_from_cart'),

    path('checkout/', views.checkout, name='checkout'),
    path('place_order/', views.place_order, name='place_order'),
    path('order_summary/<int:order_id>/', views.order_summary, name='order_summary'),
    
    

    path("request-return/<int:order_item_id>/", views.request_return, name="request_return"),
    path("user-returns/", views.user_return_requests, name="user_returns"),
    path("returns/", views.admin_return_requests, name="admin_returns"),
     path('update-return-status/', views.update_return_status, name='update_return_status'),


   # Offer Management URLs
    path('offers/', views.offer_list, name='offer_list'),
    path('create/', views.create_offer, name='create_offer'),  # Create a new offer
    path("api/offers/", views.get_offers, name="get_offers"),
    path("api/referral-offers/", views.get_referral_offers, name="referral_offers_api"),
    path("api/offers/<int:offer_id>/delete/", views.delete_offer, name="delete_offer"),
    path('toggle/<int:offer_id>/', views.toggle_offer_status, name='toggle_offer_status'),  # Activate/deactivate offer

    # Coupon Management URLs
    path('coupons/', views.coupon_list, name='coupon_list'),  # List all coupons
    path('coupons/add/', views.add_coupon, name='add_coupon'), 
    path('delete/<int:coupon_id>/', views.delete_coupon, name='delete_coupon'),  # Delete a coupon
    path('validate/', views.validate_coupon, name='validate_coupon'),  # Validate and apply coupon

    path('sales_report/', views.sales_report, name='sales_report'),
    path('sales_report/download/<str:report_type>/',views.download_sales_report, name='download_sales_report'),

    path('wishlist/', views.wishlist_view, name='wishlist_view'),
    path('wishlist/add/<int:variant_id>/', views.add_to_wishlist, name='add_to_wishlist'),
    path('wishlist/remove/<int:variant_id>/', views.remove_from_wishlist, name='remove_from_wishlist'),
    path('wishlist/add_to_cart/<int:variant_id>/', views.add_to_cart_from_wishlist, name='add_to_cart_from_wishlist'),

    path("wallet/", views.wallet_view, name="wallet"),
    path('search-results/', views.search_results, name='search_results'),

]





