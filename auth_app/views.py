import jwt
from datetime import datetime, timezone
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import models


from .permissions import check_permission  # ← импортируем из permissions.py
from .models import User, Role, UserRole, Resource, AccessRule
from .serializers import (
    UserSerializer, RegisterSerializer, 
    RoleSerializer, ResourceSerializer, AccessRuleSerializer
)


# ========== 1. Взаимодействие с пользователем ==========

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


class LoginView(APIView):
    """Вход в систему, выдача JWT токена"""
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
        
        # Генерируем JWT токен 
        payload = {
            'user_id': user.id,
            'email': user.email,
            'exp': datetime.now(timezone.utc) + settings.JWT_EXPIRATION_DELTA,
            'iat': datetime.now(timezone.utc)
        }
        token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
        
        return Response({
            'message': 'Успешный вход',
            'token': token,
            'user': UserSerializer(user).data
        })


class LogoutView(APIView):
    """Выход из системы (на клиенте нужно удалить токен)"""
    def post(self, request):
        return Response({'message': 'Выход выполнен. Удалите токен на клиенте'})


class ProfileView(APIView):
    """Получение и обновление профиля"""
    def get(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(UserSerializer(request.user).data)
    
    def put(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(APIView):
    """Мягкое удаление аккаунта (is_active = False)"""
    def post(self, request):
        if not request.user or not request.user.is_active:
            return Response({'error': 'Не авторизован'}, status=status.HTTP_401_UNAUTHORIZED)
        
        request.user.is_active = False
        request.user.save()
        return Response({'message': 'Аккаунт деактивирован'})


# ========== 2. Mock-ресурсы для демонстрации прав ==========

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