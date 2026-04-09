from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import bcrypt



class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email обязателен')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)



class User(AbstractBaseUser):
    id = models.AutoField(primary_key=True) 
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    patronymic = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    def set_password(self, raw_password):
        salt = bcrypt.gensalt()
        self.password = bcrypt.hashpw(raw_password.encode('utf-8'), salt).decode('utf-8')  
    
    
    def check_password(self, raw_password):
    return bcrypt.checkpw(raw_password.encode('utf-8'), self.password.encode('utf-8')) 
    
    def __str__(self):
        return self.email

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name

class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    
    class Meta:
        unique_together = ('user', 'role')

class Resource(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name

class AccessRule(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='access_rules')
    resource = models.ForeignKey(Resource, on_delete=models.CASCADE)
    
    can_create = models.BooleanField(default=False)
    can_read_own = models.BooleanField(default=False)
    can_read_all = models.BooleanField(default=False)
    can_update_own = models.BooleanField(default=False)
    can_update_all = models.BooleanField(default=False)
    can_delete_own = models.BooleanField(default=False)
    can_delete_all = models.BooleanField(default=False)
    
    class Meta:
        unique_together = ('role', 'resource')