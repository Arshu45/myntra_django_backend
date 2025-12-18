from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import APIException

class AccountLockedException(APIException):
    status_code = 423  # HTTP status code for Locked
    default_detail = _("Account is temporarily locked due to multiple failed login attempts.")
    default_code = "account_locked"

class EmailNotVerifiedException(APIException):
    status_code = 403  # HTTP status code for Forbidden
    default_detail = _("Email verification is required")
    default_code = "email_not_verified"

class InvalidTokenException(APIException):
    status_code = 401  # HTTP status code for Unauthorized
    default_detail = _("The provided token is invalid or has expired.")
    default_code = "invalid_token"

class RateLimitExceededException(APIException):
    status_code = 429  # HTTP status code for Too Many Requests
    default_detail = _("Rate limit exceeded. Please try again later.")
    default_code = "rate_limit_exceeded"