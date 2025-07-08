from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import User
from django.contrib.auth.hashers import check_password
import json

# Create your views here.

@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            required_fields = [
                'firstName', 'lastName', 'email', 'country', 'address',
                'countryCode', 'phone', 'password', 'confirmPassword'
            ]
            for field in required_fields:
                if not data.get(field):
                    return JsonResponse({'error': f'{field} is required.'}, status=400)
            if data['password'] != data['confirmPassword']:
                return JsonResponse({'error': 'Passwords do not match.'}, status=400)
            if data['country'] == 'Other' and not data.get('customCountry'):
                return JsonResponse({'error': 'Custom country is required.'}, status=400)
            if User.objects.filter(email=data['email']).exists():
                return JsonResponse({'error': 'Email already registered.'}, status=400)
            user = User.objects.create(
                first_name=data['firstName'],
                last_name=data['lastName'],
                email=data['email'],
                country=data['country'],
                custom_country=data.get('customCountry', ''),
                address=data['address'],
                country_code=data['countryCode'],
                phone=data['phone'],
                password=data['password'],
            )
            return JsonResponse({'success': True, 'user_id': user.id})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method.'}, status=405)

@csrf_exempt
def login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')
            if not email or not password:
                return JsonResponse({'error': 'Email and password are required.'}, status=400)
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Invalid email or password.'}, status=400)
            if check_password(password, user.password):
                return JsonResponse({'success': True, 'user_id': user.id, 'firstName': user.first_name, 'lastName': user.last_name, 'email': user.email})
            else:
                return JsonResponse({'error': 'Invalid email or password.'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method.'}, status=405)
