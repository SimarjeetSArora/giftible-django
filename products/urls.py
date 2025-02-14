from django.urls import path
from .views import ProductListCreateView, ProductDetailView, CategoryListCreateView

urlpatterns = [
    # Route to list products and create new products
    path('', ProductListCreateView.as_view(), name='product-list-create'),

    # Route to view, update, or delete a specific product
    path('<int:pk>/', ProductDetailView.as_view(), name='product-detail'),

    path('categories/', CategoryListCreateView.as_view(), name='category-list-create'),
]
