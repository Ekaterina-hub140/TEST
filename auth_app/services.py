"""
Сервисный слой для бизнес-логики.
Отделяет логику от представлений (views).
"""

from .models import User, UserRole, Role
from django.contrib.auth import get_user_model

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