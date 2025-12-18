import logging
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from authentication.serializers import UserSerializer
from authentication.core.jwt_utils import TokenManager, TokenError
from authentication.models import User
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)  # Logger for this module

class AuthenticationService:
    """
    Service layer ( Class ) for handling authentication-related operations / Business logic.
    """

    @staticmethod
    def register(email, password, phone_number=None, full_name='', request_meta=None):
        """
        Register a new user with the provided details.
        Handle user Registration with email and password.

        Args:
            email (str): User's email address.
            password (str): User's password.
            phone_number (str, optional): User's phone number.
            full_name (str, optional): User's full name.
            request_meta (dict, optional): Metadata from the request for security , logging/auditing.
        Returns:
            tuple: (success, response_dict, status_code)
        """
        from authentication.verification.services import EmailVerificationService
        if not email or not password:
            return False, {"success": False, "error": "Email and password are required."}, 400
        
        # Log Registration Attempt
        if request_meta:
            logger.info(f"Registration attempt for email: {email} from IP: {request_meta.get('REMOTE_ADDR')} at {timezone.now()}")
        
        try:
            # Check if email already exists
            if User.objects.filter(email=email).exists():
                return False, {"success": False, "error": "Email is already registered."}, 400
            
            # Validate Password Strength
            try:
                validate_password(password)
            except ValidationError as ve:
                return False, {"success": False, "error": " ".join(ve.messages)}, 400
            
            # Create new user
            user = User.objects.create_user(
                email=email,
                password=password,
                is_verified=False, # Email verification pending
            )

            # Update additional fields if provided
            if full_name:
                user.full_name = full_name
                user.save(update_fields=['full_name'])
            if phone_number:
                user.phone_number = phone_number
                user.save(update_fields=['phone_number'])


            # Queue verification email for new users (asynchronous task)
            if user.email and settings.REQUIRE_EMAIL_VERIFICATION:
                # Use Cache to mark that email verification should be sent
                cache_key = f"queue_verification_email_{user.id}"
                cache.set(cache_key, True, timeout=60*60)  # Cache for 1 hour

            # Trigger an asynchronous task to send verification email
            try:
                # Forward to Email Verification Service for sending Email
                EmailVerificationService.send_verification_email_background(user.id)
                logger.info(f"Queue Verification email for user: {user.email}")
            except Exception as thread_error:
                # Log but don't fail Registration if Email Queueing Fails
                logger.error(f"Failed to queue verification email: {str(thread_error)}")
            
        # Serialize User Data
            serializer = UserSerializer(user)

            # Generate Tokens
            tokens = TokenManager.generate_tokens(user)

            # Log Successful registration
            logger.info(f"Registration Successful for User: {user.email}")

            # Return Successful Response
            return True, {
                "success": True, 
                "data": {
                    "user": serializer.data,
                    "tokens": tokens,
                    "is_new_user": True,
                    "email_verified": user.is_verified
                }
            }, 201
    
        except Exception as e:
            return False, {"success": False, "error": "Registration Failed. Please try again! "}, 400


