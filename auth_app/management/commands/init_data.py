# auth_app/management/commands/init_data.py

from django.core.management.base import BaseCommand
from auth_app.models import Role, Resource, AccessRule, User, UserRole

class Command(BaseCommand):
    help = 'Заполняет БД тестовыми данными для демонстрации работы системы'

    def handle(self, *args, **options):
        # Создаем роли
        roles_data = [
            {'name': 'admin', 'description': 'Полный доступ ко всем ресурсам'},
            {'name': 'manager', 'description': 'Управление товарами, чтение заказов'},
            {'name': 'user', 'description': 'Обычный пользователь, может читать/создавать свои заказы'},
            {'name': 'guest', 'description': 'Гостевой доступ, только чтение товаров'},
        ]
        
        roles = {}
        for role_data in roles_data:
            role, _ = Role.objects.get_or_create(name=role_data['name'], defaults=role_data)
            roles[role_data['name']] = role
            self.stdout.write(f"Роль создана: {role.name}")
        
        # Создаем ресурсы
        resources_data = [
            {'name': 'products', 'description': 'Товары в системе'},
            {'name': 'orders', 'description': 'Заказы пользователей'},
            {'name': 'access_rules', 'description': 'Правила доступа (только для админа)'},
        ]
        
        resources = {}
        for res_data in resources_data:
            resource, _ = Resource.objects.get_or_create(name=res_data['name'], defaults=res_data)
            resources[res_data['name']] = resource
            self.stdout.write(f"Ресурс создан: {resource.name}")
        
        # Создаем правила доступа
        # Для admin: все права на все ресурсы
        for resource in resources.values():
            AccessRule.objects.get_or_create(
                role=roles['admin'],
                resource=resource,
                defaults={
                    'can_create': True,
                    'can_read_own': True,
                    'can_read_all': True,
                    'can_update_own': True,
                    'can_update_all': True,
                    'can_delete_own': True,
                    'can_delete_all': True,
                }
            )
        
        # Для manager: полный доступ к products, read_all к orders, нет доступа к access_rules
        AccessRule.objects.get_or_create(
            role=roles['manager'],
            resource=resources['products'],
            defaults={'can_create': True, 'can_read_own': True, 'can_read_all': True,
                      'can_update_own': True, 'can_update_all': True, 'can_delete_own': True, 'can_delete_all': True}
        )
        AccessRule.objects.get_or_create(
            role=roles['manager'],
            resource=resources['orders'],
            defaults={'can_create': False, 'can_read_own': True, 'can_read_all': True,
                      'can_update_own': False, 'can_update_all': False, 'can_delete_own': False, 'can_delete_all': False}
        )
        
        # Для user: может читать товары, создавать/читать/обновлять/удалять ТОЛЬКО свои заказы
        AccessRule.objects.get_or_create(
            role=roles['user'],
            resource=resources['products'],
            defaults={'can_create': False, 'can_read_own': True, 'can_read_all': False,
                      'can_update_own': False, 'can_update_all': False, 'can_delete_own': False, 'can_delete_all': False}
        )
        AccessRule.objects.get_or_create(
            role=roles['user'],
            resource=resources['orders'],
            defaults={'can_create': True, 'can_read_own': True, 'can_read_all': False,
                      'can_update_own': True, 'can_update_all': False, 'can_delete_own': True, 'can_delete_all': False}
        )
        
        # Для guest: только чтение товаров (read_all)
        AccessRule.objects.get_or_create(
            role=roles['guest'],
            resource=resources['products'],
            defaults={'can_create': False, 'can_read_own': True, 'can_read_all': True,
                      'can_update_own': False, 'can_update_all': False, 'can_delete_own': False, 'can_delete_all': False}
        )
        
        self.stdout.write(self.style.SUCCESS('Правила доступа созданы'))
        
        # Создаем тестовых пользователей
        users_data = [
            {'email': 'admin@test.com', 'password': 'admin123', 'first_name': 'Admin', 'role': 'admin'},
            {'email': 'manager@test.com', 'password': 'manager123', 'first_name': 'Manager', 'role': 'manager'},
            {'email': 'user@test.com', 'password': 'user123', 'first_name': 'User', 'role': 'user'},
            {'email': 'guest@test.com', 'password': 'guest123', 'first_name': 'Guest', 'role': 'guest'},
        ]
        
        for user_data in users_data:
            user, created = User.objects.get_or_create(
                email=user_data['email'],
                defaults={
                    'first_name': user_data['first_name'],
                    'is_active': True
                }
            )
            if created:
                user.set_password(user_data['password'])
                user.save()
                UserRole.objects.get_or_create(user=user, role=roles[user_data['role']])
                self.stdout.write(f"Пользователь создан: {user.email} (роль: {user_data['role']})")
            else:
                self.stdout.write(f"Пользователь уже существует: {user.email}")
        
        self.stdout.write(self.style.SUCCESS('Тестовые данные успешно загружены!'))