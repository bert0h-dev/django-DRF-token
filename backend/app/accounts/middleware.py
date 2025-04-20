import datetime
from django.utils.timezone import now

class LastActivityMiddleware:
  def __init__(self, get_response):
    self.get_response = get_response

  def __call__(self, request):
    user = getattr(request, 'user', None)

    if user and user.is_authenticated:
      last_seen = user.last_activity
      now_time = now()
      # Actualiza solo si han pasado al menos 1 minuto para reducir escritura
      if not last_seen or (now_time - last_seen).total_seconds() > 60:
        user.last_activity = now_time
        user.save(update_fields=['last_activity'])

    return self.get_response(request)