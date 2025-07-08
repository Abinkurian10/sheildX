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

@csrf_exempt
def scan_url(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url')
            if not url:
                return JsonResponse({'error': 'URL is required.'}, status=400)

            import requests
            from urllib.parse import urlparse

            results = []

            # 1. SQL Injection Test
            payload = "' OR 1=1--"
            parsed = urlparse(url)
            test_url = url
            if parsed.query:
                base = url.split('?', 1)[0]
                params = parsed.query.split('&')
                if params:
                    key = params[0].split('=')[0]
                    test_url = f"{base}?{key}={payload}"
            else:
                sep = '&' if '?' in url else '?'
                test_url = f"{url}{sep}test={payload}"
            try:
                normal_resp = requests.get(url, timeout=5)
                inj_resp = requests.get(test_url, timeout=5)
            except Exception as e:
                return JsonResponse({'error': f'Failed to fetch URL: {str(e)}'}, status=400)
            is_vulnerable = False
            if normal_resp.status_code == inj_resp.status_code:
                if len(normal_resp.text) != len(inj_resp.text):
                    is_vulnerable = True
            else:
                is_vulnerable = True
            results.append({
                'name': 'SQL Injection',
                'score': 30 if is_vulnerable else 90,
                'details': 'Possible SQL injection vulnerability detected.' if is_vulnerable else 'No SQL injection vulnerability detected.'
            })

            # 2. XSS Vulnerability Test
            xss_payload = '<script>alert(1)</script>'
            xss_url = url
            if parsed.query:
                base = url.split('?', 1)[0]
                params = parsed.query.split('&')
                if params:
                    key = params[0].split('=')[0]
                    xss_url = f"{base}?{key}={xss_payload}"
            else:
                sep = '&' if '?' in url else '?'
                xss_url = f"{url}{sep}test={xss_payload}"
            try:
                xss_resp = requests.get(xss_url, timeout=5)
                xss_found = xss_payload in xss_resp.text
            except Exception:
                xss_found = False
            results.append({
                'name': 'XSS Vulnerability',
                'score': 30 if xss_found else 90,
                'details': 'Potential reflected XSS found.' if xss_found else 'No reflected XSS detected.'
            })

            # 3. HTTP Header Security
            headers = normal_resp.headers
            missing_headers = []
            recommended_headers = [
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'Referrer-Policy',
                'Permissions-Policy',
            ]
            for h in recommended_headers:
                if h not in headers:
                    missing_headers.append(h)
            score = 90 if not missing_headers else 60
            results.append({
                'name': 'HTTP Header Security',
                'score': score,
                'details': 'All recommended security headers are present.' if not missing_headers else f"Missing headers: {', '.join(missing_headers)}."
            })

            # 4. Insecure Cookie Detection
            cookies = normal_resp.cookies
            insecure_cookies = []
            for c in cookies:
                if not c.secure or not c.has_nonstandard_attr('HttpOnly'):
                    insecure_cookies.append(c.name)
            score = 90 if not insecure_cookies else 60
            results.append({
                'name': 'Insecure Cookie Detection',
                'score': score,
                'details': 'All cookies have Secure and HttpOnly flags.' if not insecure_cookies else f"Some cookies lack Secure/HttpOnly: {', '.join(insecure_cookies)}."
            })

            # 5. Clickjacking Risk
            xfo = headers.get('X-Frame-Options', '')
            if xfo.lower() in ['deny', 'sameorigin']:
                score = 95
                details = 'X-Frame-Options header is set correctly.'
            else:
                score = 50
                details = 'X-Frame-Options header is missing or misconfigured.'
            results.append({
                'name': 'Clickjacking Risk',
                'score': score,
                'details': details
            })

            # 6. Misconfigured Security Headers
            csp = headers.get('Content-Security-Policy', '')
            if csp:
                score = 90
                details = 'Content-Security-Policy header is present.'
            else:
                score = 50
                details = 'Content-Security-Policy header is missing.'
            results.append({
                'name': 'Misconfigured Security Headers',
                'score': score,
                'details': details
            })

            return JsonResponse({'results': results})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method.'}, status=405)
