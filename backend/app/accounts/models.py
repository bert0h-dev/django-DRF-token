from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone

class CustomUserManager(BaseUserManager):
  def create_user(self, email, username, password=None, **extra_fields):
    if not email:
        raise ValueError('El correo electrónico es obligatorio')
    if not username:
        raise ValueError('El nombre de usuario es obligatorio')

    email = self.normalize_email(email)
    user = self.model(email=email, username=username, **extra_fields)
    user.set_password(password)
    user.save(using=self._db)
    return user

  def create_superuser(self, email, username, password=None, **extra_fields):
    extra_fields.setdefault('is_staff', True)
    extra_fields.setdefault('is_superuser', True)
    extra_fields.setdefault('is_verified', True)

    return self.create_user(email, username, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
  # Identificación
  email = models.EmailField(unique=True)
  username = models.CharField(max_length=150, unique=True)
  first_name = models.CharField(max_length=150, blank=True)
  last_name = models.CharField(max_length=150, blank=True)

  # Perfil
  avatar = models.ImageField(upload_to="avatars/", null=True, blank=True)
  department = models.CharField(max_length=100, blank=True, null=True)
  position = models.CharField(max_length=100, blank=True, null=True)
  phone_number = models.CharField(max_length=20, blank=True, null=True)

  # Preferencias
  language = models.CharField(max_length=10, default='es')
  timezone = models.CharField(max_length=50, default='America/Mexico_City')

  # Seguridad
  is_verified = models.BooleanField(default=False) # Verificación por correo
  requires_password_change = models.BooleanField(default=True) # Cambio forzado tras primer login
  password_changed = models.BooleanField(default=False)  # Para enviar alerta si se cambia
  last_ip = models.GenericIPAddressField(null=True, blank=True)  # Para alertas de inicio de sesión

  # Sistema
  is_active = models.BooleanField(default=True)
  is_staff = models.BooleanField(default=False)
  date_joined = models.DateTimeField(default=timezone.now)
  last_activity = models.DateTimeField(null=True, blank=True)

  USERNAME_FIELD = 'email'
  REQUIRED_FIELDS = ['username']

  def __str__(self):
    return self.email

  def set_password(self, raw_password):
    super().set_password(raw_password)
    self.password_changed = True
    self.requires_password_change = False
    self.save()