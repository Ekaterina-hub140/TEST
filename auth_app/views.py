import jwt
from datetime import datetime, timezone
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiResponse

from .permissions import check_permission
from .services import TokenService
from .models import User, Role, UserRole, Resource, AccessRule
from .serializers import (
    UserSerializer, RegisterSerializer, 
    RoleSerializer, ResourceSerializer, AccessRuleSerializer
)


# ========== 1. Взаимодействие с пользователем ==========

@extend_schema(
    summary="Регистрация пользователя",
    description="Создаёт нового пользователя с ролью 'user' по умолчанию",
    request=RegisterSerializer,
    responses={
        201: UserSerializer,
        400: OpenApiResponse(description="Ошибка валидации (пароли не совпадают, email уже существует)"),
    }
)
class RegisterView(APIView):
    """Регистрация нового пользователя"""
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            # По умолчанию назначаем роль "user" (если существует)
            try:
                default_role = Role.objects.get(name='user')
                UserRole.objects.get_or_create(user=user, role=default_role)
            except Role.DoesNotExist:
                pass
            return Response(
                {'message': 'Пользователь успешно зарегистрирован', 'user': UserSerializer(user).data},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    summary="Вход в систему",
    description="Аутентификация по email и паролю. Возвращает access_token и refresh_token",
    request={
        "type": "object",
        "properties": {
            "email": {"type": "string", "format": "email", "example": "user@test.com"},
            "password": {"type": "string", "format": "password", "example": "user123"},
        },
        "required": ["email", "password"]
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "access_token": {"type": "string"},
                "refresh_token": {"type": "string"},
                "user": {"type": "object"},
            }
        },
        400: OpenApiResponse(description="Email и пароль обязательны"),
        401: OpenApiResponse(description="Неверный email или пароль"),
    }
)
class LoginView(APIView):
    """Вход в систему, выдача JWT токенов"""
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response(
                {'error': 'Email и пароль обязательны'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return Response(
                {'error': 'Неверный email или пароль'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        if not user.check_password(password):
            return Response(
                {'error': 'Неверный email или пароль'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Генерируем access JWT токен
        payload = {
            'user_id': user.pk,
            'email': user.email,
            'exp': datetime.now(timezone.utc) + settings.JWT_EXPIRATION_DELTA,
            'iat': datetime.now(timezone.utc)
        }
        access_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        
        # Генерируем refresh токен
        refresh_token = TokenService.generate_refresh_token(user)
        
        return Response({
            'message': 'Успешный вход',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': UserSerializer(user).data
        })


@extend_schema(
    summary="Обновление access-токена",
    description="Получение нового access-токена по refresh-токену",
    request={
        "type": "object",
        "properties": {
            "refresh_token": {"type": "string", "example": "eyJhbGciOiJIUzI1NiIs..."},
        },
        "required": ["refresh_token"]
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "access_token": {"type": "string"},
            }
        },
        401: OpenApiResponse(description="Невалидный или просроченный refresh токен"),
    }
)
class RefreshTokenView(APIView):
    """Обновление access-токена"""
    def post(self, request):
        refresh_token_str = request.data.get('refresh_token')
        
        if not refresh_token_str:
            return Response(
                {'error': 'Refresh token required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        access_token, error = TokenService.refresh_access_token(refresh_token_str)
        
        if error:
            return Response(
                {'error': error},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        return Response({
            'access_token': access_token
        })


@extend_schema(
    summary="Выход из системы",
    description="Отзыв refresh-токена. Access-токен удаляется на клиенте.",
    request={
        "type": "object",
        "properties": {
            "refresh_token": {"type": "string"},
        }
    },
    responses={
        200: OpenApiResponse(description="Выход выполнен"),
    }
)
class LogoutView(APIView):
    """Выход из системы (отзыв refresh-токена)"""
    def post(self, request):
        refresh_token_str = request.data.get('refresh_token')
        
        if refresh_token_str:
            TokenService.revoke_refresh_token(refresh_token_str)
        
        return Response({'message': 'Выход выполнен. Refresh токен отозван.'})


@extend_schema(
    summary="Получение профиля",
    description="Возвращает информацию о текущем пользователе",
    responses={
        200: UserSerializer,
        401: OpenApiResponse(description="Не авторизован"),
    }
)
class ProfileView(APIView):
    """Получение и обновление профиля"""
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(UserSerializer(request.user).data)
    
    @extend_schema(
        summary="Обновление профиля",
        description="Частичное обновление данных пользователя",
        request=UserSerializer,
        responses={
            200: UserSerializer,
            401: OpenApiResponse(description="Не авторизован"),
            400: OpenApiResponse(description="Ошибка валидации"),
        }
    )
    def put(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema(
    summary="Мягкое удаление аккаунта",
    description="Деактивирует аккаунт (is_active=False). Пользователь больше не может войти.",
    responses={
        200: OpenApiResponse(description="Аккаунт деактивирован"),
        401: OpenApiResponse(description="Не авторизован"),
    }
)
class DeleteAccountView(APIView):
    """Мягкое удаление аккаунта (is_active = False)"""
    def post(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        request.user.is_active = False
        request.user.save()
        return Response({'message': 'Аккаунт деактивирован'})


# ========== 2. Mock-ресурсы для демонстрации прав ==========

@extend_schema(
    summary="Товары (mock)",
    description="Демонстрация прав доступа к ресурсу 'products'",
    responses={
        200: {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "products": {"type": "array"},
            }
        },
        401: OpenApiResponse(description="Не авторизован"),
        403: OpenApiResponse(description="Доступ запрещён"),
    }
)
class MockProductsView(APIView):
    """Вымышленный ресурс 'products' для проверки прав"""
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if check_permission(request.user, 'products', 'read', is_own=False):
            return Response({
                'message': 'Доступ к товарам разрешен',
                'products': [
                    {'id': 1, 'name': 'Товар 1', 'price': 100},
                    {'id': 2, 'name': 'Товар 2', 'price': 200},
                ]
            })
        return Response(
            {'error': 'Доступ запрещен', 'required': 'read permission for products'},
            status=status.HTTP_403_FORBIDDEN
        )
    
    def post(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if check_permission(request.user, 'products', 'create'):
            return Response({'message': 'Товар создан', 'product': request.data})
        return Response({'error': 'Нет прав на создание товаров'}, status=status.HTTP_403_FORBIDDEN)


@extend_schema(
    summary="Заказы (mock)",
    description="Демонстрация прав доступа к ресурсу 'orders' с разделением на свои/чужие",
    parameters=[
        {
            "name": "own",
            "in": "query",
            "type": "boolean",
            "description": "true — только свои заказы, false — все заказы",
            "required": False,
        }
    ],
    responses={
        200: {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "orders": {"type": "array"},
            }
        },
        401: OpenApiResponse(description="Не авторизован"),
        403: OpenApiResponse(description="Доступ запрещён"),
    }
)
class MockOrdersView(APIView):
    """Вымышленный ресурс 'orders' для проверки прав с разделением на 'свои' и 'чужие'"""
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        is_own = request.query_params.get('own', 'false').lower() == 'true'
        
        if check_permission(request.user, 'orders', 'read', is_own=is_own):
            if is_own:
                return Response({
                    'message': f'Свои заказы пользователя {request.user.email}',
                    'orders': [{'id': 1, 'user': request.user.email, 'total': 500}]
                })
            return Response({
                'message': 'Все заказы системы',
                'orders': [
                    {'id': 1, 'user': 'user1@example.com', 'total': 500},
                    {'id': 2, 'user': 'user2@example.com', 'total': 1500},
                ]
            })
        return Response({'error': 'Доступ запрещен'}, status=status.HTTP_403_FORBIDDEN)


# ========== 3. API для администратора (управление правилами доступа) ==========

class AdminRoleListView(APIView):
    """Список ролей (только для админов)"""
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'read'):
            return Response({'error': 'Доступ запрещен'}, status=status.HTTP_403_FORBIDDEN)
        
        roles = Role.objects.all()
        return Response(RoleSerializer(roles, many=True).data)
    
    def post(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'create'):
            return Response({'error': 'Нет прав на создание ролей'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminResourceListView(APIView):
    """Список ресурсов (только для админов)"""
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'read'):
            return Response({'error': 'Доступ запрещен'}, status=status.HTTP_403_FORBIDDEN)
        
        resources = Resource.objects.all()
        return Response(ResourceSerializer(resources, many=True).data)
    
    def post(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'create'):
            return Response({'error': 'Нет прав'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = ResourceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminAccessRuleListView(APIView):
    """Управление правилами доступа"""
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'read'):
            return Response({'error': 'Доступ запрещен'}, status=status.HTTP_403_FORBIDDEN)
        
        rules = AccessRule.objects.select_related('role', 'resource').all()
        return Response(AccessRuleSerializer(rules, many=True).data)
    
    def post(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'create'):
            return Response({'error': 'Нет прав на создание правил'}, status=status.HTTP_403_FORBIDDEN)
        
        serializer = AccessRuleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AdminAccessRuleDetailView(APIView):
    """Изменение и удаление конкретного правила"""
    def get_rule(self, pk):
        try:
            return AccessRule.objects.get(pk=pk)
        except AccessRule.DoesNotExist:
            return None
    
    def put(self, request, pk):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'update'):
            return Response({'error': 'Нет прав на изменение правил'}, status=status.HTTP_403_FORBIDDEN)
        
        rule = self.get_rule(pk)
        if not rule:
            return Response({'error': 'Правило не найдено'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = AccessRuleSerializer(rule, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not check_permission(request.user, 'access_rules', 'delete'):
            return Response({'error': 'Нет прав на удаление правил'}, status=status.HTTP_403_FORBIDDEN)
        
        rule = self.get_rule(pk)
        if not rule:
            return Response({'error': 'Правило не найдено'}, status=status.HTTP_404_NOT_FOUND)
        
        rule.delete()
        return Response({'message': 'Правило удалено'})