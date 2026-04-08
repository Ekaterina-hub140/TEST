import jwt
from django.conf import settings
from django.http import JsonResponse
from .models import User

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        request.user = None
        
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            try:
                payload = jwt.decode(
                    token, 
                    settings.JWT_SECRET_KEY, 
                    algorithms=[settings.JWT_ALGORITHM]
                )
                user_id = payload.get('user_id')
                if user_id:
                    try:
                        request.user = User.objects.get(id=user_id, is_active=True)
                    except User.DoesNotExist:
                        pass
            except jwt.ExpiredSignatureError:
                pass
            except jwt.InvalidTokenError:
                pass
        
        response = self.get_response(request)
        return response