import logging
import threading
import traceback
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .emails import EmailService

logger = logging.getLogger(__name__)  # Logger for this module

User = get_user_model()

class EmailVerificationService:
    """
    Service layer for handling email verification operations.
    """

    @staticmethod
    def get_verification_cache_key(user_id):
        """
        Get standardized cache key for storing verification codes.
        """
        return f"email_verification:{user_id}"
    
    @staticmethod
    def send_verification_email(user):
        """
        Send a verification email to the user.

        Args:
            user (User): The user instance to send the email to.
        Returns:
            Tuple : (success, response_dict, status_code)
        """

        try:
            if user.is_verified:
                return True, {"success": True, "error": "User is already verified."}, 200
            
            # Rate Limiting Per User
            rate_key = f"verification_email_{user.id}"
            if cache.get(rate_key):
                # Get time remaining for rate limit
                timeout_value = 300
                return False, {"success": False, "error": f"Please wait {timeout_value} seconds before requesting another verification email."}, 429
            

            # Queue Verification Email to be Send (asynchronous)
            try:
                # Queue verification email to be sent asynchronously
                threading.Thread(
                    target=EmailVerificationService.send_verification_email_background,
                    args=(user.id),
                    daemon=True
                ).start()

                # Set Rate Limiting regardless of background thread success
                cache.set(rate_key, True, timeout=300)  # 5 minutes rate limit
                logger.info(f"Verification email queued for user ID: {user.id}")
                return True, {"success": True, "message": "Verification email is being sent. Please Check your inbox"}, 200
            except Exception as thread_error:
                logger.error(f"Failed to queue verification email thread for user ID {user.id}: {str(thread_error)}")
                logger.error(traceback.format_exc())
                return False, {"success": False, "error": "Failed to send verification email. Please Try Again later."}, 500
        except Exception as e:
            logger.error(f"Send Verification Email Error: {str(e)}")
            return False, {"success": False, "error": "Failed to send verification email. Please Try Again later."}, 400

    @staticmethod
    def send_verification_email_background(user_id):
        """
        Background method for sending verification email.

        Args:
            user_id (int): ID of the user to send the email to.
        Returns:
            None    
        """
        # Forward to Email Service for sending Email
        try:
            # Queue verification email with retry
            EmailService.send_verification_email_with_retry(user_id, 3)
            logger.info(f"Background Verification email queued for user ID: {user_id}")
        except Exception as e:
            logger.error(f"Failed to queue verification email for user ID {user_id}: {str(e)}")
            logger.error(traceback.format_exc())

