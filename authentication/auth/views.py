import logging
import traceback
from django.utils import timezone
from django.conf import settings
from django.middleware.csrf import get_token
from datetime import timedelta

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny # Permission classes to control access to views
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle # Throttling classes to limit request rates ( Rate Limiting )
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.core.base_view import BaseAPIView
from authentication.core.response import standardized_response
from .services import AuthenticationService


logger = logging.getLogger(__name__) # Logger for this module

class UserRegistrationView(BaseAPIView):
    """
    API view to handle user registration.
    """
    permission_classes = [AllowAny]  # Allow any user (authenticated or not) to access this view
    throttle_classes = [AnonRateThrottle]  # Apply rate limiting for anonymous users

    def post(self, request):
        """
        Handle POST request for user registration.
        """
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            phone_number = request.data.get('phone_number')
            full_name = request.data.get('full_name', '')

            # Using service layer to handle registration logic
            success, response_data, status_code = AuthenticationService.register(
                email=email,
                password=password,
                phone_number=phone_number,
                full_name=full_name,
                request_meta=request.META
            )

            # Create Response Object
            response = Response(
                standardized_response(**response_data),
                status=status_code
            )

            # Set Refresh token Cookie if registration was successful and cookie security is enabled
            if success and status_code in (200, 201) and settings.JWT_COOKIE_SECURE:
                tokens = response_data.get('data', {}).get('tokens', {})
                if 'refresh_token' in tokens and 'request_expires_in' in tokens:
                    response.set_cookie(
                        key=settings.JWT_COOKIE_NAME,
                        value=tokens['refresh_token'],
                        expires=timezone.now() + timedelta(seconds=tokens['refresh_expires_in']),
                        secure=True,
                        httponly=True,
                        samesite="Strict",
                        path="/",
                        domain=settings.SESSION_COOKIE_DOMAIN
                    )

            if success:
                get_token(request)

            return response
        except Exception as e:
            logger.error(f"User registration failed: {str(e)}")
            logger.error(traceback.format_exc())
            return Response(
                standardized_response(
                    success=False,
                    error="Registration failed",
                    message=str(e),
                    status=status.HTTP_400_BAD_REQUEST
                )
            )