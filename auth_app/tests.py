from django.test import TestCase
from rest_framework.test import APIClient
from auth_app.models import User, Role

class AuthTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.role, _ = Role.objects.get_or_create(name='user')
        
    def test_register_success(self):
        response = self.client.post('/api/register/', {
            'email': 'newuser@test.com',
            'password': 'testpass123',
            'password2': 'testpass123',
            'first_name': 'Test'
        })
        self.assertEqual(response.status_code, 201)
        self.assertTrue(User.objects.filter(email='newuser@test.com').exists())
    
    def test_register_password_mismatch(self):
        response = self.client.post('/api/register/', {
            'email': 'newuser@test.com',
            'password': 'pass123',
            'password2': 'pass456',
        })
        self.assertEqual(response.status_code, 400)
    
    def test_login_success(self):
        User.objects.create_user(email='test@test.com', password='testpass123')
        
        response = self.client.post('/api/login/', {
            'email': 'test@test.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json())
    
    def test_login_wrong_password(self):
        User.objects.create_user(email='test@test.com', password='testpass123')
        
        response = self.client.post('/api/login/', {
            'email': 'test@test.com',
            'password': 'wrongpass'
        })
        self.assertEqual(response.status_code, 401)
    
    def test_protected_endpoint_without_token(self):
        # Без токена — анонимный пользователь, доступ запрещён
        response = self.client.get('/api/mock/products/')
        self.assertEqual(response.status_code, 403)  # Forbidden, не 401