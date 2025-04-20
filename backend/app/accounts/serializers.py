from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from django.urls import reverse
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth import get_user_model, models

from datetime import timedelta

from .models import User
from .utils.token_generator import (
  generate_email_token, 
  generate_password_reset_token, 
  verify_password_reset_token
)

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
  password = serializers.CharField(write_only=True)

  class Meta:
    model = User
    fields = ['email', 'username', 'password', 'first_name', 'last_name']

  def create(self, validated_data):
    user = User.objects.create_user(
      email=validated_data['email'],
      username=validated_data['username'],
      password=validated_data['password'],
      first_name=validated_data.get('first_name', ''),
      last_name=validated_data.get('last_name', '')
    )
    user.is_verified = False
    user.requires_password_change = True
    user.save()

    # Token y URL de verificación
    token = generate_email_token(user)
    url = self.context['request'].build_absolute_uri(
      reverse('verify-email') + f"?token={token}"
    )

    expiration_time = timezone.now() + timedelta(hours=24)
    expiration_str = expiration_time.strftime("%d %B %Y %H:%M")

    # Enviar correo
    send_mail(
      subject='Verifica tu cuenta',
      message=f'Haz clic en el siguiente enlace para verificar tu cuenta:\n\n{url}\n\nEste enlace expirará el {expiration_str}.',
      from_email=None,
      recipient_list=[user.email],
    )

    return user

class ResendVerificationEmailSerializer(serializers.Serializer):
  email = serializers.EmailField()

  def validate_email(self, value):
    try:
      user = User.objects.get(email=value)
    except User.DoesNotExist:
      raise serializers.ValidationError("No existe un usuario con ese correo.")

    if user.is_verified:
      raise serializers.ValidationError("Este usuario ya está verificado.")

    return value

  def save(self, **kwargs):
    user = User.objects.get(email=self.validated_data['email'])

    token = generate_email_token(user)
    url = self.context['request'].build_absolute_uri(
      reverse('verify-email') + f"?token={token}"
    )

    expiration_time = timezone.now() + timedelta(hours=24)
    expiration_str = expiration_time.strftime("%d %B %Y %H:%M")

    send_mail(
      subject='Reenvío de verificación de cuenta',
      message=f'Haz clic para verificar tu cuenta:\n\n{url}\n\nEste enlace expirará el {expiration_str}.',
      from_email=None,
      recipient_list=[user.email],
    )

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
  def validate(self, attrs):
    data = super().validate(attrs)

    if not self.user.is_verified:
      raise serializers.ValidationError("Tu cuenta aún no ha sido verificada por correo.")

    data['user'] = {
      "id": self.user.id,
      "email": self.user.email,
      "username": self.user.username,
      "requires_password_change": self.user.requires_password_change,
    }

    return data

class ChangePasswordSerializer(serializers.Serializer):
  old_password = serializers.CharField(write_only=True)
  new_password = serializers.CharField(write_only=True)

  def validate_old_password(self, value):
    user = self.context['request'].user
    if not user.check_password(value):
      raise serializers.ValidationError("La contraseña actual no es correcta.")
    return value

  def validate_new_password(self, value):
    if len(value) < 8:
      raise serializers.ValidationError("La nueva contraseña debe tener al menos 8 caracteres.")
    return value

  def update(self, instance, validated_data):
    instance.set_password(validated_data['new_password'])
    instance.save()
    return instance

class UserProfileSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = [
      'id', 'email', 'username',
      'first_name', 'last_name',
      'avatar', 'department',
      'phone_number', 'language', 'timezone',
      'is_verified', 'is_staff', 'is_superuser',
      'date_joined', 'last_activity'
    ]
    read_only_fields = ['id', 'email', 'is_verified', 'is_staff', 'is_superuser', 'date_joined', 'last_activity']

class UserAdminUpdateSerializer(serializers.ModelSerializer):
  class Meta:
    model = User
    fields = [
        'username', 'first_name', 'last_name',
        'avatar', 'department', 'phone_number',
        'language', 'timezone',
        'is_active', 'is_staff', 'is_superuser',
        'groups', 'user_permissions'
    ]

  # Para mostrar IDs en grupos/permisos y permitir edición
  groups = serializers.PrimaryKeyRelatedField(many=True, queryset=models.Group.objects.all())
  user_permissions = serializers.PrimaryKeyRelatedField(many=True, queryset=models.Permission.objects.all())

class RequestPasswordResetSerializer(serializers.Serializer):
  email = serializers.EmailField()

  def validate_email(self, value):
    try:
      user = User.objects.get(email=value)
      if not user.is_verified:
        raise serializers.ValidationError("Tu cuenta aún no está verificada.")
    except User.DoesNotExist:
      raise serializers.ValidationError("No existe un usuario con este correo.")
    return value

  def save(self):
    email = self.validated_data['email']
    user = User.objects.get(email=email)
    token = generate_password_reset_token(user)

    # Enlace para el frontend
    url = self.context['request'].build_absolute_uri(
      reverse('validate-reset-token') + f'?token={token}'
    )

    expiration = timezone.now() + timedelta(hours=24)
    expiration_str = expiration.strftime('%d %B %Y %H:%M')

    send_mail(
      subject='Restablece tu contraseña',
      message=f'Usa el siguiente enlace para restablecer tu contraseña:\n\n{url}\n\nEste enlace expira el {expiration_str}.',
      from_email=None,
      recipient_list=[user.email]
    )

class ValidateResetTokenSerializer(serializers.Serializer):
  token = serializers.CharField()

  def validate_token(self, value):
    user_id = verify_password_reset_token(value)
    if not user_id:
      raise serializers.ValidationError("Token inválido o expirado.")
    return value

class ResetPasswordConfirmSerializer(serializers.Serializer):
  token = serializers.CharField()
  new_password = serializers.CharField(min_length=8)

  def validate(self, data):
    user_id = verify_password_reset_token(data['token'])
    if not user_id:
      raise serializers.ValidationError({"token": "Token inválido o expirado."})

    self.user = User.objects.filter(id=user_id).first()
    if not self.user:
      raise serializers.ValidationError({"token": "Usuario no encontrado."})

    return data

  def save(self):
    password = self.validated_data['new_password']
    self.user.set_password(password)
    self.user.save()
    return self.user

# Manejo de roles y permisos
class PermissionSerializer(serializers.ModelSerializer):
  content_type = serializers.StringRelatedField()

  class Meta:
    model = models.Permission
    fields = ['id', 'name', 'codename', 'content_type']

class GroupSerializer(serializers.ModelSerializer):
  permissions = serializers.PrimaryKeyRelatedField(
    many=True,
    queryset=models.Permission.objects.all()
  )
  permission_ids = serializers.PrimaryKeyRelatedField(
    many=True,
    queryset=models.Permission.objects.all(),
    write_only=True,
    source='permissions'
  )

  class Meta:
    model = models.Group
    fields = ['id', 'name', 'permissions', 'permission_ids']

  def validate_name(self, value):
    # Si es creación y ya existe el nombre
    if self.instance is None and models.Group.objects.filter(name=value).exists():
      raise serializers.ValidationError("Ya existe un grupo con este nombre.")
    return value

  def validate_permissions(self, value):
    for perm in value:
      if not isinstance(perm, models.Permission):
        raise serializers.ValidationError("Permiso inválido.")
    return value

class UserGroupUpdateSerializer(serializers.ModelSerializer):
  groups = serializers.PrimaryKeyRelatedField(
    queryset=models.Group.objects.all(),
    many=True
  )

  class Meta:
    model = User
    fields = ['id', 'username', 'email', 'groups']
    read_only_fields = ['id', 'username', 'email']

  def validate_groups(self, value):
    for group in value:
      if not isinstance(group, models.Group):
        raise serializers.ValidationError("Permiso inválido.")
    return value

class UserGroupListSerializer(serializers.ModelSerializer):
  class Meta:
    model = models.Group
    fields = ['id', 'name']

class PermissionSerializer(serializers.ModelSerializer):
  content_type = serializers.StringRelatedField()

  class Meta:
    model = models.Permission
    fields = ['id', 'name', 'codename', 'content_type']