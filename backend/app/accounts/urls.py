from django.urls import include, path

from rest_framework.routers import DefaultRouter

from .views import (
    # Autenticación
    RegisterView, LoginView, LogoutView, ChangePasswordView,
    VerifyEmailView, ResendVerificationEmailView,

    # Perfil
    MeView, MyGroupsView, MyPermissionsView,

    # Admin - usuarios, grupos, permisos
    AdminUpdateUserView, AssignGroupsToUserView,
    GroupViewSet, PermissionViewSet,

    # Reset de contraseña
    RequestPasswordResetView, ValidateResetTokenView, ResetPasswordConfirmView,
)

rAdmin = DefaultRouter()
rAdmin.register('groups', GroupViewSet, basename='group')
rAdmin.register('permissions', PermissionViewSet, basename='permission')

urlpatterns = [
    # Registro, login, logout
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='logout'),
    path('logout/', LogoutView.as_view(), name='logout'),

    # Verificación de correo
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),

    # Cambio de contraseña
    path('password/change/', ChangePasswordView.as_view(), name='change-password'),

    # Restablecimiento de contraseñas por token
    path('password/reset/', RequestPasswordResetView.as_view(), name='request-reset'),
    path('password/validate-token/', ValidateResetTokenView.as_view(), name='validate-reset-token'),
    path('password/confirm/', ResetPasswordConfirmView.as_view(), name='confirm-reset'),

    # Perfil del usuario actual
    path('me/', MeView.as_view(), name='me'),
    path('me/groups/', MyGroupsView.as_view(), name='my-groups'),
    path('me/permissions/', MyPermissionsView.as_view(), name='my-permissions'),
    
    # Administracion de usuarios (solo admin)
    path('admin/users/<int:pk>/update/', AdminUpdateUserView.as_view(), name='admin-update-user'),
    path('admin/users/<int:pk>/groups/', AssignGroupsToUserView.as_view(), name='assign-groups'),
    
    # CRUD de grupos y permisos
    path('admin/', include(rAdmin.urls)), 
]