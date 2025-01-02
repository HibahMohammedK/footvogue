from django.urls import path
from . import views



urlpatterns = [
    path('',views.login_view, name='login'),
    path('home/',views.home, name='home'),
    path('register/',views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),

    path('admin_dash/', views.admin_dash, name='admin_dash'),
    path('admin_users/', views.admin_user_management, name='admin_users'),
    
] 
 