# urls.py
from django.urls import path
from .views import RegisterView,LoginView,LogoutView,PasswordResetView,PasswordResetConfirmView,  ClientListCreateView, ClientDetailView

urlpatterns = [
    path('account/register/', RegisterView.as_view(), name='register'),
    path('account/login/', LoginView.as_view(), name='login'),
    path('account/logout/', LogoutView.as_view(), name='logout'),
    path('account/resetPwd/', PasswordResetView.as_view(), name='resetPWD'),
    path('account/reset/<str:uidb64>/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    path('client/', ClientListCreateView.as_view(), name='client-list-create'),
    path('client/<int:pk>/', ClientDetailView.as_view(), name='client-detail'),
   
]
