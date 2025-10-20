from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.contrib.messages import get_messages


class RegisterViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        # Adjust this URL name to match your urls.py
        try:
            self.register_url = reverse('register')
        except:
            self.register_url = '/users/register/'
    
    def test_register_get_request_returns_form(self):
        """Test that GET request returns registration form"""
        response = self.client.get(self.register_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)
        self.assertTemplateUsed(response, 'users/register.html')
    
    def test_register_post_valid_data_creates_user(self):
        """Test successful user registration with valid data"""
        response = self.client.post(self.register_url, {
            'username': 'testuser',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!',
            'email': 'test@example.com',
            'name': 'John',
            'lastname': 'Doe'
        })
        
        # Verify user was created
        self.assertTrue(User.objects.filter(username='testuser').exists())
        user = User.objects.get(username='testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')
        
        # Verify success message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('successful' in str(m).lower() for m in messages))
        
        # Verify redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.url)
    
    def test_register_strips_whitespace_from_fields(self):
        """Test that whitespace is stripped from email and name fields"""
        self.client.post(self.register_url, {
            'username': 'testuser',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!',
            'email': '  test@example.com  ',
            'name': '  John  ',
            'lastname': '  Doe  '
        })
        
        user = User.objects.get(username='testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe')
    
    def test_register_duplicate_email_shows_error(self):
        """Test that registering with existing email shows error"""
        # Create existing user
        User.objects.create_user(
            username='existinguser',
            email='test@example.com',
            password='TestPass123!'
        )
        
        response = self.client.post(self.register_url, {
            'username': 'newuser',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!',
            'email': 'test@example.com',
            'name': 'Jane',
            'lastname': 'Smith'
        })
        
        # Verify new user was not created
        self.assertFalse(User.objects.filter(username='newuser').exists())
        
        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('email already exists' in str(m).lower() for m in messages))
        
        # Verify redirect back to register
        self.assertEqual(response.status_code, 302)
        self.assertIn('/register', response.url)
    
    def test_register_invalid_form_shows_error(self):
        """Test that invalid form data shows error message"""
        response = self.client.post(self.register_url, {
            'username': 'testuser',
            'password1': 'TestPass123!',
            'password2': 'DifferentPass123!',  # Passwords don't match
            'email': 'test@example.com'
        })
        
        # Verify user was not created
        self.assertFalse(User.objects.filter(username='testuser').exists())
        
        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('correct the errors' in str(m).lower() for m in messages))
        
        # Verify form with errors is returned
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)
        self.assertFalse(response.context['form'].is_valid())
    
    def test_register_missing_optional_fields(self):
        """Test registration works without optional name fields"""
        self.client.post(self.register_url, {
            'username': 'testuser',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!'
        })
        
        user = User.objects.get(username='testuser')
        self.assertEqual(user.email, '')
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, '')
    
    def test_register_duplicate_username_shows_error(self):
        """Test that registering with existing username shows error"""
        # Create existing user
        User.objects.create_user(
            username='testuser',
            email='existing@example.com',
            password='TestPass123!'
        )
        
        response = self.client.post(self.register_url, {
            'username': 'testuser',
            'password1': 'TestPass123!',
            'password2': 'TestPass123!',
            'email': 'new@example.com'
        })
        
        # Verify form has errors
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)
        self.assertFalse(response.context['form'].is_valid())


class LoginViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        # Adjust this URL name to match your urls.py
        try:
            self.login_url = reverse('login')
        except:
            self.login_url = '/users/login/'
        
        self.user = User.objects.create_user(
            username='testuser',
            password='TestPass123!',
            first_name='John'
        )
    
    def test_login_get_request_returns_form(self):
        """Test that GET request returns login form"""
        response = self.client.get(self.login_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)
        self.assertTemplateUsed(response, 'users/login.html')
    
    def test_login_post_valid_credentials_logs_in_user(self):
        """Test successful login with valid credentials"""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPass123!'
        })
        
        # Verify user is logged in
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        self.assertEqual(response.wsgi_request.user.username, 'testuser')
        
        # Verify success message includes first name
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Welcome back, John!' in str(m) for m in messages))
        
        # Verify redirect to profile
        self.assertEqual(response.status_code, 302)
        self.assertIn('/profile', response.url)
    
    def test_login_user_without_first_name_uses_username(self):
        """Test that username is used in welcome message if first_name is empty"""
        user_no_name = User.objects.create_user(
            username='usernoname',
            password='TestPass123!',
            first_name=''
        )
        
        response = self.client.post(self.login_url, {
            'username': 'usernoname',
            'password': 'TestPass123!'
        })
        
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Welcome back, usernoname!' in str(m) for m in messages))
    
    def test_login_post_invalid_credentials_shows_error(self):
        """Test that invalid credentials show error message"""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'WrongPassword123!'
        })
        
        # Verify user is not logged in
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        
        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid username or password' in str(m) for m in messages))
        
        # Verify form is returned
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)
    
    def test_login_post_nonexistent_user_shows_error(self):
        """Test that nonexistent username shows error message"""
        response = self.client.post(self.login_url, {
            'username': 'nonexistent',
            'password': 'TestPass123!'
        })
        
        # Verify user is not logged in
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        
        # Verify error message
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('Invalid username or password' in str(m) for m in messages))
        
        # Verify form is returned
        self.assertEqual(response.status_code, 200)
    
    def test_login_empty_credentials_shows_error(self):
        """Test that empty credentials show error message"""
        response = self.client.post(self.login_url, {
            'username': '',
            'password': ''
        })
        
        # Verify user is not logged in
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        
        # Verify error message (either form validation or custom message)
        messages = list(get_messages(response.wsgi_request))
        # Check for either custom message or form errors
        has_error = (
            any('Invalid username or password' in str(m) for m in messages) or
            (response.status_code == 200 and 'form' in response.context and 
             not response.context['form'].is_valid())
        )
        self.assertTrue(has_error)
        
        # Verify form is returned
        self.assertEqual(response.status_code, 200)
    
    def test_login_case_sensitive_username(self):
        """Test that username is case-sensitive"""
        response = self.client.post(self.login_url, {
            'username': 'TESTUSER',  # Wrong case
            'password': 'TestPass123!'
        })
        
        # Verify user is not logged in
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        self.assertEqual(response.status_code, 200)
    
    def test_login_maintains_session_after_login(self):
        """Test that user session is maintained after successful login"""
        # Login
        self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'TestPass123!'
        })
        
        # Make another request to verify session persists
        response = self.client.get(self.login_url)
        self.assertTrue(response.wsgi_request.user.is_authenticated)
        self.assertEqual(response.wsgi_request.user.username, 'testuser')