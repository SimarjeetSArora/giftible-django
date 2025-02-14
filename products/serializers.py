from rest_framework import serializers
from .models import Product, ProductImage, Category

class ProductImageSerializer(serializers.ModelSerializer):
     class Meta:
        model = ProductImage
        fields = ['id', 'image']  # Only return image URLs

class ProductSerializer(serializers.ModelSerializer):
    images = ProductImageSerializer(many=True, read_only=True)  # ✅ Correct way to handle RelatedManager
    category = serializers.PrimaryKeyRelatedField(queryset=Category.objects.all(), required=True)

    class Meta:
        model = Product
        fields = ['id', 'name', 'description', 'price', 'quantity', 'ngo', 'category', 'is_visible', 'created_at', 'updated_at', 'images']  # Add more fields as needed

    def create(self, validated_data):
        """ Create product and handle multiple images """
        request = self.context.get('request')  # Get request from serializer context
        images = request.FILES.getlist('images')  # Get multiple images from request

        product = Product.objects.create(**validated_data)  # ✅ Create Product first

        for image in images:  # ✅ Loop through images & create ProductImage entries
            ProductImage.objects.create(product=product, image=image)

        return product

    def update(self, instance, validated_data):
        images_data = validated_data.pop('images', None)
        
        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Update images if necessary
        if images_data is not None:
            instance.images.all().delete()  # Delete old images (optional)
            for image_data in images_data:
                ProductImage.objects.create(product=instance, **image_data)

        instance.save()
        return instance

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', 'description']