"""
Сервисный слой для бизнес-логики.
Отделяет логику от представлений (views).
"""

from .models import User, UserRole, Role
from django.contrib.auth import get_user_model
import secrets
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from .models import RefreshToken

User = get_user_model()


class UserService:
    """Сервис для работы с пользователями"""
    
    @staticmethod
    def register_user(email: str, password: str, first_name: str = "", last_name: str = "", patronymic: str = ""):
        """Регистрация нового пользователя"""
        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            patronymic=patronymic
        )
        
        # Назначить роль по умолчанию
        try:
            default_role = Role.objects.get(name='user')
            UserRole.objects.get_or_create(user=user, role=default_role)
        except Role.DoesNotExist:
            pass
        
        return user
    
    @staticmethod
    def soft_delete_user(user: User):
        """Мягкое удаление аккаунта"""
        user.is_active = False
        user.save()
        return user


class TokenService:
    """Сервис для работы с JWT токенами"""
    
    @staticmethod
    def generate_token(user_id: int, email: str, expiration_delta):
        """Генерация JWT токена"""
        import jwt
        from datetime import datetime, timezone
        from django.conf import settings
        
        payload = {
            'user_id': user_id,
            'email': email,
            'exp': datetime.now(timezone.utc) + expiration_delta,
            'iat': datetime.now(timezone.utc)
        }
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    @staticmethod
    def generate_refresh_token(user):
        """Генерация refresh-токена"""
        token = secrets.token_urlsafe(64)
        expires_at = timezone.now() + timedelta(days=settings.REFRESH_TOKEN_EXPIRATION_DAYS)
        
        refresh_token = RefreshToken.objects.create(
            user=user,
            token=token,
            expires_at=expires_at
        )
        return token
    
    @staticmethod
    def refresh_access_token(refresh_token_str):
        """Обновление access-токена по refresh-токену"""
        try:
            refresh_token = RefreshToken.objects.get(
                token=refresh_token_str,
                is_revoked=False
            )
        except RefreshToken.DoesNotExist:
            return None, "Invalid refresh token"
        
        if refresh_token.is_expired():
            return None, "Refresh token expired"
        
        # Генерируем новый access-токен
        access_token = TokenService.generate_token(
            refresh_token.user.id,
            refresh_token.user.email,
            settings.JWT_EXPIRATION_DELTA
        )
        
        return access_token, None
    
    @staticmethod
    def revoke_refresh_token(refresh_token_str):
        """Отзыв refresh-токена (при logout)"""
        try:
            refresh_token = RefreshToken.objects.get(token=refresh_token_str)
            refresh_token.is_revoked = True
            refresh_token.save()
            return True
        except RefreshToken.DoesNotExist:
            return False