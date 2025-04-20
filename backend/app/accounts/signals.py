from django.db.models.signals import post_migrate, user_logged_in
from django.dispatch import receiver
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.utils.timezone import now
from django.conf import settings
from django.core.mail import send_mail

from django.contrib.auth import get_user_model
User = get_user_model()

# 🎯 Crear grupos por defecto automáticamente
@receiver(post_migrate)
def create_default_groups(sender, **kwargs):
  default_groups = {
    "Admin": ['add_user', 'change_user', 'delete_user', 'view_user'],
  }

  user_ct = ContentType.objects.get_for_model(User)

  for group_name, perms in default_groups.items():
    group, created = Group.objects.get_or_create(name=group_name)
    for codename in perms:
      perm, _ = Permission.objects.get_or_create(codename=codename, content_type=user_ct)
      group.permissions.add(perm)

  ## Si se quieren agregar los permisos de un modelo a un grupo en especifico ya creado se hace asi
  # content_type = ContentType.objects.get_for_model(modeloEjemplo)
  # perm = Permission.objects.get(codename='view_project', content_type=content_type)
  # group.permissions.add(perm)

# 🧠 Opcional: loguear o notificar inicio de sesión desde IP desconocida
@receiver(user_logged_in)
def notify_login(sender, request, user, **kwargs):
  ip = request.META.get('REMOTE_ADDR')
  if user.last_ip and user.last_ip != ip:
    # Enviar notificación crítica
    send_mail(
        subject='Inicio de sesión desde nueva IP',
        message=f'Se detectó un nuevo inicio de sesión para tu cuenta desde IP: {ip}',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
    )
  user.last_ip = ip
  user.last_activity = now()
  user.save(update_fields=['last_ip', 'last_activity'])