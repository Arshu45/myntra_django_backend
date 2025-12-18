import logging
import traceback
import time
import random
import string

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger(__name__)  # Logger for this module

class EmailService:
    """
    Service for sending user verification emails.
    """

    @staticmethod
    def send_verification_email(user):
        """
        Sends a verification email to the user with both link and code.
        Args:
            user (User): The user instance to send the email to.
        Returns:
            bool: True if email sent successfully, False otherwise.
        """
        try:
            # Generate verification token for Link
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Create Verification Link
            verify_url = f"{settings.FRONTEND_URL}/auth/email-verify?uid={uid}&token={token}"

            # Compose Email
            subject = f"{settings.APP_NAME} - Verify Your Email Address"

            # Template context
            context = {
                'user': user,
                'verify_url': verify_url,
                'app_name': settings.APP_NAME,
                'code_expiry': '1 Hour'
            }

            try:
                # Render HTML email Template
                html_message = render_to_string('emails/verify_email.html', context)

                # Plain text message as fallback
                plain_message = f"Hi {user.email},\nPlease verify your email by clicking the link below:\n{verify_url}\nThis link will expire in 1 hour. \n\nThank you,\n{settings.APP_NAME} Team"

            except Exception as template_error:
                # Fallback to plain text email if template rendering fails
                logger.error(f"Email template rendering failed: {str(template_error)}")
                html_message = None
                plain_message = f"Hi {user.email},\nPlease verify your email by clicking the link below:\n{verify_url}\nThis link will expire in 1 hour. \n\nThank you,\n{settings.APP_NAME} Team"


            # Verify SMTP Settings before sending
            try:
                # Check if Email_HOST_User and EMail_PASSWORD are set
                if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
                    logger.error("SMTP settings ( Email Credentials ) are not properly configured.")
                    return False
                
                from_email = settings.DEFAULT_FROM_EMAIL or settings.EMAIL_HOST_USER
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=from_email,
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False,
                )

                logger.info(f"Verification email sent to {user.email}")
                return True
            except Exception as smtp_error:
                logger.error(f"Failed to send verification email to {user.email}: {str(smtp_error)}")
                logger.error(traceback.format_exc())
                return False
        except Exception as e:
            logger.error(f"Unexpected error in send_verification_email: {str(e)}")
            logger.error(traceback.format_exc())
            return False


    @staticmethod
    def send_verification_email_with_retry(user_id, max_attempts=3):
        try:
            # Get User by ID
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                logger.error(f"Background verification email sending failed: User with ID {user_id} does not exist.")
                return
            
            # Check if already verified
            if user.is_verified:
                logger.info(f"User with ID {user_id} is already verified. No email sent.")
                return
            
            # Make Multiple Attempts to Send Email wit Exponential Backoff
            for attempt in range(1, max_attempts + 1):
                try:
                    success = EmailService.send_verification_email(user)
                    if success:
                        logger.info(f"Verification email successfully sent to user ID {user_id} on attempt {attempt}.")
                        return
                    else:
                        logger.error(f"Attempt {attempt} to send verification email to user ID {user_id} failed.")
                except Exception as send_error:
                    logger.error(f"Error on attempt {attempt} to send verification email to user ID {user_id}: {str(send_error)}")
                    
                
                # Exponential Backoff before next attempts
                if attempt < max_attempts:
                    backoff_time = 2 ** attempt + random.uniform(0, 1)
                    time.sleep(backoff_time)
            logger.error(f"All {max_attempts} attempts to send verification email to user ID {user_id} have failed.")
        except Exception as e:
            logger.error(f"Unexpected error in send_verification_email_with_retry for user ID {user_id}: {str(e)}")
            logger.error(traceback.format_exc())


