from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from datetime import timedelta, datetime
from django.conf import settings
from django.core.cache import cache
import jwt
import logging
import uuid
import time
from django.utils import timezone

logger = logging.getLogger(__name__)

class TokenManager:

    """" Enhanced JWT Token Manager for generating, blacklisting, and validating tokens."""

    @staticmethod
    def generate_tokens(user):
        """
        Generate secure access and refresh tokens for a given user with enhanced claims and security.
        """
        try:
            refresh = RefreshToken.for_user(user)
            
            # Create Unique JTI (JWT ID) for better Tracking
            jti = str(uuid.uuid4())

            # Add custom claims with security enhancements
            refresh['jti'] = jti
            refresh['username'] = user.username
            refresh['is_staff'] = user.is_staff
            refresh['is_verified'] = user.is_verified
            refresh['email'] = user.email
            refresh['type'] = 'refresh'

            # Setup different claims for access token
            access_token = refresh.access_token
            access_token['type'] = 'access'
            access_token['jti'] = str(uuid.uuid4())  # New JTI for access token

            # Get Expiration times
            access_expiry = settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME', timedelta(minutes=15))
            refresh_expiry = settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME', timedelta(days=7))

            # Store Token Metadata in Cache for potential revocation checks
            TokenManager._store_token_metadata(jti, user.id, refresh_expiry.total_seconds())

            # Return the tokens as strings
            return {
                'access_token': str(access_token),
                'refresh_token': str(refresh),
                'token_type': 'Bearer',
                'expires_in': int(access_expiry.total_seconds()),
                'refresh_expires_in': int(refresh_expiry.total_seconds()),
                'user_id': user.id, 
                'issued_at': int(timezone.now().timestamp())
            }
    
        except Exception as e:
            logger.error(f"Failed to generate tokens for user {user.id}: {str(e)}")
            raise

    @staticmethod
    def refresh_tokens(refresh_token):
        """
        Refresh access tokens with validation and optional rotation.
        """
        try:
            refresh = RefreshToken(refresh_token)

            # Check if token is blacklisted
            jti = refresh.get('jti')
            if not jti or TokenManager.is_token_blacklisted(jti):
                logger.warning(f"Attempt to use blacklisted refresh token: {refresh_token}")
                raise TokenError("Token is blacklisted")

            # Get User from token
            user_id = refresh.get('user_id')
            from authentication.models import User

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                logger.warning(f"User not found for ID: {user_id}")
                raise TokenError("User does not exist")
            
            # Check if user is still active
            if not user.is_active:
                logger.warning(f"Inactive user attempted token refresh: {user_id}")
                # Blacklist the token
                TokenManager.blacklist_token(jti) 
                raise TokenError("User is inactive")
            # If token rotation is enabled, blacklist the old refresh token
            if settings.SIMPLE_JWT.get('ROTATE_REFRESH_TOKENS', False):
                TokenManager.blacklist_token(jti)
            
            # Generate new tokens
            return TokenManager.generate_tokens(user)
        except TokenError as e:
            logger.error(f"Failed to refresh tokens: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during token refresh: {str(e)}")
            raise TokenError(f"Token refresh failed: {str(e)}")

    @staticmethod
    def blacklist_token(jti):
        """
        Blacklist a token by its JTI.
        """
        if not jti:
            return False
        # Add the JTI to the blacklist in cache with expiry
        try:
            blacklist_key = f"blacklisted_tokens: {jti}"
            # Set a key in cache to mark the token as blacklisted
            cache.set(blacklist_key, True, timeout=settings.SIMPLE_JWT.get('BLACKLIST_TIMEOUT', 86400))  # Default 1 day
            logger.info(f"Token blacklisted with JTI: {jti}")
        except Exception as e:
            logger.error(f"Failed to blacklist token with JTI {jti}: {str(e)}")

    @staticmethod
    def _store_token_metadata(jti, user_id, expiry_seconds):
        """
        Store token metadata in cache for blacklisting.
        """
        try:
            if hasattr(cache, 'client'):
                # Redis Implementation
                user_tokens_key = f"user_tokens: {user_id}"
                pipe = cache.client.pipeline()
                pipe.sadd(user_tokens_key, jti)
                pipe.expire(user_tokens_key, int(expiry_seconds))
                pipe.execute()
            else:
                # Generic Implementation for LocMemCache
                user_tokens_key = f"user_tokens: {user_id}"
                token_set = cache.get(user_tokens_key, set())
                if not isinstance(token_set, set):
                    token_set = set()
                token_set.add(jti)
                cache.set(user_tokens_key, token_set, timeout=expiry_seconds)
        except Exception as e:
            logger.error(f"Failed to store token metadata: {str(e)}")

    @staticmethod
    def is_token_blacklisted(jti):
        """
        Check if a token is blacklisted.
        """
        if not jti:
            return False
        blacklist_key = f"blacklisted_tokens: {jti}"
        return cache.get(blacklist_key) is not None
    
    @staticmethod
    def validate_token(token):
        """
        Validate Token without using the Database.
        Returns Tuple (is_valid: bool, user_id: int or None, Token_Type: str or None)
        """
        try:
            # First Use pyJWT to decode without verification to get the Algorithm
            unverified = jwt.decode(token, options={"verify_signature": False})
            alg = unverified.get('alg', settings.SIMPLE_JWT.get('ALGORITHM', 'HS256'))

            # Now Properly Decode and Verify
            decoded = jwt.decode(
                token,
                settings.SIMPLE_JWT.get('SIGNING_KEY', settings.SECRET_KEY),
                algorithms=[alg],
                options={
                    'verify_signature': True
                }
            )

            # Check token type
            token_type = decoded.get('token_type', decoded.get('type', 'access'))
            user_id = decoded.get('user_id')
            jti = decoded.get('jti')

            # Check if token is blacklisted
            if jti and TokenManager.is_token_blacklisted(jti):
                logger.warning(f"Blacklisted token used: JTI {jti}")
                return (False, None, None)
            
            # check expiration
            exp = decoded.get('exp', 0)
            if exp < time.time():
                logger.debug(f"Token expired: JTI {jti} at {datetime.fromtimestamp(exp).isoformat()}")
                return (False, None, None)
            return (True, user_id, token_type)
        except jwt.PyJWTError as e:
            logger.debug("Token has expired.")
            return (False, None, None)
        

    @staticmethod
    def blacklist_all_user_tokens(user_id):
        """
        Blacklist all tokens associated with a user.
        """
        try:
            user_tokens_key = f"user_tokens: {user_id}"
            if hasattr(cache, 'client'):
                # Redis Implementation
                active_tokens = cache.client.smembers(user_tokens_key)
                if not active_tokens:
                    return 0
                
                # Add each token to blacklist
                for jti in active_tokens:
                    TokenManager.blacklist_token(jti.decode('utf-8') if isinstance(jti, bytes) else jti)

                # Clear the set
                cache.delete(user_tokens_key)
                return len(active_tokens)
            else:
                # Generic Implementation for LocMemCache
                token_set = cache.get(user_tokens_key, set())
                if not token_set:
                    return 0

                # Blacklist each token
                for jti in token_set:
                    TokenManager.blacklist_token(jti)
                # Clear the set
                cache.delete(user_tokens_key)
                return len(token_set)
        except Exception as e:
            logger.error(f"Failed to blacklist all tokens for user {user_id}: {str(e)}")
            return 0
        
    def get_token_payload(token):
        """
        Decode token and return its payload without verification.
        """
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
        except jwt.PyJWTError as e:
            logger.error(f"Failed to decode token payload: {str(e)}")
            return None