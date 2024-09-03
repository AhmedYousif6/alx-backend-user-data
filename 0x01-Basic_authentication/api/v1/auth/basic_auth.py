""" BasicAuth system module
"""
from .auth import Auth
import base64
import re
import binascii
from typing import Tuple, TypeVar
from models.user import User


class BasicAuth(Auth):
    """ Basic authentication system class
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str
            ) -> str:
        """ return the base64 part of authorization header
        """
        if authorization_header is None:
            return None
        if type(authorization_header) != str:
            return None
        pattern = r'Basic (?P<token>.+)'
        field_match = re.fullmatch(pattern, authorization_header.strip())
        if field_match is None:
            return None
        return field_match.group('token')

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str
            ) -> str:
        """ return the decode value of a Base64 string
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) != str:
            return None
        try:
            res = base64.b64decode(base64_authorization_header, validate=True)
            return res.decode('utf-8')
        except (binascii.Error, UnicodeDecodeError):
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
            ) -> Tuple[str, str]:
        """ extract user name and password
        """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern, decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return (user, password)
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str, user_pwd: str
            ) -> TypeVar('User'):
        """Retrieves a user based on the user's authentication credentials.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retrieves the user from a request
        """
        auth_header = self.authorization_header(request)
        b_64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b_64_auth_token)
        email, pwd = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, pwd)
