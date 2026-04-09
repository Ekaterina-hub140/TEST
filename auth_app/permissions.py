"""
Модуль для проверки прав доступа.
Вынесен из views.py для чистой архитектуры.
"""

from .models import User, Resource, AccessRule, UserRole


def check_permission(user: User, resource_name: str, action: str, is_own: bool = False) -> bool:
    """
    Проверяет, есть ли у пользователя доступ к ресурсу.
    
    Args:
        user: Объект пользователя
        resource_name: Название ресурса ('products', 'orders', 'access_rules')
        action: Действие ('create', 'read', 'update', 'delete')
        is_own: True - доступ к своим объектам, False - ко всем
    
    Returns:
        bool: Есть ли доступ
    """
    if not user or not user.is_active:
        return False
    
    user_roles = UserRole.objects.filter(user=user).select_related('role')
    
    for ur in user_roles:
        try:
            resource = Resource.objects.get(name=resource_name)
            rule = AccessRule.objects.get(role=ur.role, resource=resource)
            
            if action == 'create' and rule.can_create:
                return True
            elif action == 'read':
                if is_own and rule.can_read_own:
                    return True
                if rule.can_read_all:
                    return True
            elif action == 'update':
                if is_own and rule.can_update_own:
                    return True
                if rule.can_update_all:
                    return True
            elif action == 'delete':
                if is_own and rule.can_delete_own:
                    return True
                if rule.can_delete_all:
                    return True
        except (Resource.DoesNotExist, AccessRule.DoesNotExist):
            continue
    
    return False