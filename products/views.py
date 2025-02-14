from rest_framework import generics, permissions
from .models import Product, Category
from .serializers import ProductSerializer, CategorySerializer
from users.models import CustomUser
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from .models import ProductImage
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

class ProductPagination(PageNumberPagination):
    page_size = 9  # ✅ Show 9 products per page
    page_size_query_param = 'page_size'
    max_page_size = 50  # Optional: Limit max products per page

class ProductListCreateView(generics.ListCreateAPIView):
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # Allow file uploads
    pagination_class = ProductPagination  # ✅ Pagination applies only to listing
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ["category", "ngo", "price"]  # ✅ Filters for category, NGO, and price
    ordering_fields = ["price", "created_at"]  # ✅ Allow sorting by price or creation date

    def get_queryset(self):
        queryset = Product.objects.all()
        
        # If NGO user is logged in, show only their products
        if self.request.user.is_ngo:
            queryset = queryset.filter(ngo=self.request.user)

        return queryset

    def perform_create(self, serializer):
        product = serializer.save(ngo=self.request.user)  # Save product first

        # 🛠 Debug: Print request.FILES to see what Django is receiving
        print("FILES:", self.request.FILES)

        # ✅ Check if 'images' exists before accessing it
        images = self.request.FILES.getlist('images') if 'images' in self.request.FILES else []
        for image in images:
            ProductImage.objects.create(product=product, image=image)

        return Response({"message": "Product created successfully"}, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        """
        Override list to apply pagination explicitly for GET requests.
        """
        queryset = self.filter_queryset(self.get_queryset())  # ✅ Apply filters

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class ProductDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    View, Update, or Delete a Product.
    - Anyone can view a product.
    - Only the NGO that created it can update/delete.
    """
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """
        - GET: All users can retrieve product details.
        - PUT/DELETE: Only the NGO that created it can modify.
        """
        if self.request.method in ["PUT", "PATCH", "DELETE"]:
            return Product.objects.filter(ngo=self.request.user)
        return Product.objects.all()

    def perform_update(self, serializer):
        """
        Updates product details.
        - If images are provided, update them.
        - If no images are provided, keep the existing ones.
        """
        images = self.request.FILES.getlist("images")
        if images:  # Only update images if new ones are uploaded
            serializer.save(images=images)
        else:
            serializer.save(partial=True)  # Ensures PATCH works as expected

    def perform_destroy(self, instance):
        """
        - Ensures only the NGO that created it can delete.
        - Optionally, delete associated files (e.g., images).
        """
        if instance.ngo != self.request.user:
            raise PermissionDenied("You do not have permission to delete this product.")
        instance.delete()

class CategoryListCreateView(generics.ListCreateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticated]  # Optional: restrict to authenticated users

    def perform_create(self, serializer):
        """Override to add custom behavior (e.g., assigning a user)"""
        serializer.save()  # You can add more logic here if needed