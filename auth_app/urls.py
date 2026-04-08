from django.urls import path
from . import views

urlpatterns = [
    # Пользовательские endpoints
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('delete-account/', views.DeleteAccountView.as_view(), name='delete-account'),
    
    # Mock-ресурсы для демонстрации прав
    path('mock/products/', views.MockProductsView.as_view(), name='mock-products'),
    path('mock/orders/', views.MockOrdersView.as_view(), name='mock-orders'),
    
    # Админские endpoints (управление правами)
    path('admin/roles/', views.AdminRoleListView.as_view(), name='admin-roles'),
    path('admin/resources/', views.AdminResourceListView.as_view(), name='admin-resources'),
    path('admin/access-rules/', views.AdminAccessRuleListView.as_view(), name='admin-access-rules'),
    path('admin/access-rules/<int:pk>/', views.AdminAccessRuleDetailView.as_view(), name='admin-access-rule-detail'),
]