import traceback 
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .response import standardized_response

logger = logging.getLogger(__name__)

class BaseAPIView(APIView):
    """
    A base view that provides common functionality for all API views,
    including error handling and standardized responses formatting.
    """

    def handle_exception(self, exc):
        """
        Handle exceptions raised in the view.
        Logs the exception and returns a standardized error response.
        Standardize exception handling for all API views.
        """
        if isinstance(exc, AuthenticationFailed):
            logger.warning(f"Authentication failed: {str(exc)}")
            return Response(
                standardized_response(
                    success=False,
                    error="Authentication failed",
                    message=str(exc),
                    status=status.HTTP_401_UNAUTHORIZED
                )
            )
        elif isinstance(exc, (InvalidToken, TokenError)):
            logger.warning(f"Invalid token: {str(exc)}")
            return Response(
                standardized_response(
                    success=False,
                    error="Invalid token",
                    message=str(exc),
                    status=status.HTTP_401_UNAUTHORIZED
                )
            )
        else:
            logger.error(f"Unexpected error: {str(exc)}")
            return Response(
                standardized_response(
                    success=False,
                    error="Unexpected error",
                    message=str(exc),
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            )

    
