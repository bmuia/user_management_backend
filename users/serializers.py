from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password

User = get_user_model()

class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=4)
    password2 = serializers.CharField(write_only=True, min_length=4)

    class Meta:
        model = User
        fields = ('email', 'password','password2')
        extra_kwargs = {
            'password': {'write_only': True},
            'password2': {'write_only': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'] 
        )
        return user
    
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ('email', 'password')

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','email', 'full_name','profile_picture','is_verified', 'is_active', 'is_staff', 'is_verified','date_of_birth', 'phone_number', 'address', 'gender', 'country', 'referral_code', 'bio','date_joined','last_login')
        read_only_fields = ('is_active', 'is_verified', 'is_staff','date_joined','last_login')

class AdminUserUpdateSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = [
            'is_active',
            'is_staff',
            'is_verified',
            'password',
        ]
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
        }

    def update(self, instance, validated_data):
        """
        Update a user instance with the validated data.  Handles password hashing.
        """
        password = validated_data.pop('password', None)  # Remove password, handle separately
        for attr, value in validated_data.items():
            setattr(instance, attr, value)  # Update other fields
        if password:
            instance.set_password(password)  # Hash the password
        instance.save()  # Save the changes to the database
        return instance

        