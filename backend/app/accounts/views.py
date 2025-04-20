from rest_framework import generics, status, permissions, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from django.urls import reverse
from django.contrib.auth import get_user_model, models
from django.core.mail import send_mail

from .models import User
from .serializers import (
  RegisterSerializer,
  CustomTokenObtainPairSerializer,
  RequestPasswordResetSerializer,
  ResendVerificationEmailSerializer,
  ChangePasswordSerializer,
  ResetPasswordConfirmSerializer,
  UserAdminUpdateSerializer,
  UserGroupListSerializer,
  UserGroupUpdateSerializer,
  UserProfileSerializer,
  PermissionSerializer,
  GroupSerializer,
  ValidateResetTokenSerializer,
)
from .utils.token_generator import verify_email_token

User = get_user_model()

class RegisterView(generics.CreateAPIView):
  serializer_class = RegisterSerializer

  def post(self, request, *args, **kwargs):
    serializer = self.get_serializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    return Response({"message": "Registro exitoso. Revisa tu correo para verificar tu cuenta."}, status=status.HTTP_201_CREATED)

class VerifyEmailView(APIView):
  def get(self, request):
    token = request.query_params.get("token")
    user_id = verify_email_token(token)

    if not user_id:
        return Response({"error": "El enlace de verificación ha expirado o es inválido."}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(id=user_id).first()
    if not user:
        return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)

    user.is_verified = True
    user.save()
    return Response({"message": "Correo verificado correctamente. Ya puedes iniciar sesión."}, status=status.HTTP_200_OK)

class ResendVerificationEmailView(generics.GenericAPIView):
  serializer_class = ResendVerificationEmailSerializer

  def post(self, request, *args, **kwargs):
    serializer = self.get_serializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({"message": "Correo de verificación reenviado."}, status=status.HTTP_200_OK)

class LoginView(APIView):
  def post(self, request):
    serializer = CustomTokenObtainPairSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response(serializer.validated_data, status=status.HTTP_200_OK)

class LogoutView(APIView):
  permission_classes = [permissions.IsAuthenticated]

  def post(self, request):
    try:
      refresh_token = request.data["refresh"]
      token = RefreshToken(refresh_token)
      token.blacklist()
      return Response(status=status.HTTP_205_RESET_CONTENT)
    except KeyError:
      return Response({"error": "Se requiere refresh token."}, status=status.HTTP_400_BAD_REQUEST)
    except TokenError:
      return Response({"error": "Token inválido o ya expirado."}, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(generics.UpdateAPIView):
  serializer_class = ChangePasswordSerializer
  permission_classes = [permissions.IsAuthenticated]

  def get_object(self):
    return self.request.user

  def update(self, request, *args, **kwargs):
    user = self.get_object()
    if not user.is_verified:
      return Response({"error": "Debes verificar tu correo antes de cambiar tu contraseña."}, status=status.HTTP_400_BAD_REQUEST)

    return super().update(request, *args, **kwargs)

class MeView(generics.RetrieveAPIView):
  serializer_class = UserProfileSerializer
  permission_classes = [permissions.IsAuthenticated]

  def get_object(self):
      return self.request.user

# 1. Solicitar restablecimiento
class RequestPasswordResetView(generics.GenericAPIView):
  serializer_class = RequestPasswordResetSerializer

  def post(self, request):
    serializer = self.get_serializer(data=request.data, context={"request": request})
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({"message": "Se envió un correo con instrucciones para restablecer tu contraseña."}, status=200)

# 2. Verificar token (opcional, útil para frontend)
class ValidateResetTokenView(generics.GenericAPIView):
  serializer_class = ValidateResetTokenSerializer

  def get(self, request):
    serializer = self.get_serializer(data=request.query_params)
    serializer.is_valid(raise_exception=True)
    return Response({"message": "Token válido."}, status=200)

# 3. Enviar nueva contraseña
class ResetPasswordConfirmView(generics.GenericAPIView):
  serializer_class = ResetPasswordConfirmSerializer

  def post(self, request):
    serializer = self.get_serializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({"message": "Contraseña actualizada correctamente."}, status=200)

# Manejo de roles y permisos
class AdminUpdateUserView(generics.RetrieveUpdateAPIView):
  queryset = User.objects.all()
  serializer_class = UserAdminUpdateSerializer
  permission_classes = [permissions.IsAdminUser]

class PermissionViewSet(viewsets.ReadOnlyModelViewSet):
  queryset = models.Permission.objects.select_related('content_type').all().order_by('content_type__app_label', 'codename')
  serializer_class = PermissionSerializer
  permission_classes = [permissions.IsAdminUser]  # Solo accesible para admins

class GroupViewSet(viewsets.ModelViewSet):
  queryset = models.Group.objects.prefetch_related('permissions').all().order_by('name')
  serializer_class = GroupSerializer
  permission_classes = [permissions.IsAdminUser]

class AssignGroupsToUserView(generics.UpdateAPIView):
  queryset = User.objects.all()
  serializer_class = UserGroupUpdateSerializer
  permission_classes = [permissions.IsAdminUser]

class MyGroupsView(APIView):
  permission_classes = [permissions.IsAuthenticated]

  def get(self, request):
    user = request.user
    groups = user.groups.all()
    serializer = UserGroupListSerializer(groups, many=True)
    return Response(serializer.data)

class MyPermissionsView(APIView):
  permission_classes = [permissions.IsAuthenticated]

  def get(self, request):
    user = request.user

    # Permisos directos + de grupos
    permissions = models.Permission.objects.filter(user=user) | models.Permission.objects.filter(group__user=user)
    permissions = permissions.distinct().select_related('content_type').order_by('content_type__app_label', 'codename')

    serializer = PermissionSerializer(permissions, many=True)
    return Response(serializer.data)