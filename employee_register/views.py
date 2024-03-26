from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes,force_str
from django.core.mail import send_mail
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework.response import Response
from .models import  Client
from .serializers import  ClientSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication






class ClientListCreateView(generics.ListCreateAPIView):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer

class ClientDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Client.objects.all()
    serializer_class = ClientSerializer
    

    
class RegisterView(APIView):
    def post(self, request):
        serializer = ClientSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            name = serializer.validated_data['name']
            password = serializer.validated_data['password']

            user = Client.objects.create_user(email=email, name=name, password=password)
            token = Token.objects.create(user=user)
            
            return Response({'token': token.key, 'user_id': user.id}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        print(f"{email} {password}")
        user = authenticate(request, email=email, password=password)

        if user is None:
            raise AuthenticationFailed('Invalid email or password')

        token, created = Token.objects.get_or_create(user=user)

        return Response({'token': token.key, 'user_id': user.id}, status=status.HTTP_200_OK)

class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.auth.delete()

        return Response({'detail': 'Successfully logged out.'})
    
    
    
class PasswordResetView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = Client.objects.filter(email=email).first()

        if user is not None:
            # Generate a password reset token
            token = default_token_generator.make_token(user)

            # Create a link with the reset token
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"http://localhost:8000/api/reset/{uidb64}/{token}/"

            # Construct the email subject and body
            subject = 'Password Reset Request'
            message = render_to_string('registrations/password_reset_email.html', {'reset_link': reset_link})
            from_email = 'mehdimhadbi15@gmail.com'
            recipient_list = [user.email]

            # Send the reset link through email
            send_mail(subject, message, from_email, recipient_list)

            return Response({'detail': 'Password reset link sent'}, status=status.HTTP_200_OK)

        return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class PasswordResetConfirmView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            print(f"uidb64 in the URL: {uidb64}")   
            user = Client.objects.get(pk=uid)

            # Check if the token is valid
            if default_token_generator.check_token(user, token):
                # Reset the user's password to a temporary one (for demonstration)
                new_password = 'temporary_password'
                user.set_password(new_password)
                user.save()

                return Response({'detail': 'Password reset successful'}, status=status.HTTP_200_OK)

            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        except (TypeError, ValueError, OverflowError, Client.DoesNotExist):
            return Response({'detail': 'Invalid user ID'}, status=status.HTTP_400_BAD_REQUEST)
        
