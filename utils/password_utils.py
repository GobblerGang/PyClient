import re
from typing import Tuple, List
import requests
import hashlib

class PasswordValidator:
    def __init__(self):
        self.min_length = 8
        self.max_length = 64
        self.common_passwords = self._load_common_passwords()

    def _load_common_passwords(self) -> List[str]:
        """Load a list of common passwords to check against using HaveIBeenPwned API."""
        try:
            # Using the HaveIBeenPwned API
            response = requests.get('https://api.pwnedpasswords.com/range/00000')
            if response.status_code == 200:
                # Extract just the hashes from the response
                return [line.split(':')[0] for line in response.text.splitlines()]
        except:
            pass

        # Fallback to a comprehensive list of common passwords if API fails
        return [
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'letmein',
            'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine', 'master',
            'welcome', 'shadow', 'ashley', 'football', 'jesus', 'michael', 'ninja', 'mustang',
            'password1', '123456789', 'password123', 'admin123', 'qwerty123', 'welcome123',
            'login', 'admin', 'user', 'pass', 'pass123', '1234', '12345', '1234567890',
            'qwertyuiop', '1q2w3e4r', '1qaz2wsx', 'zaq1zaq1', 'qazwsx', 'qwerty1', '123qwe',
            'adminadmin', 'password1234', '12341234', 'qwer1234', 'admin1', 'test123',
            '123123123', '11111111', '00000000', '22222222', '33333333', '44444444',
            '55555555', '66666666', '77777777', '88888888', '99999999', 'qwertyui',
            'asdfghjk', 'zxcvbnm', 'qwerty123456', 'admin123456', 'password123456',
            '123456qwerty', 'qwerty123456789', 'admin123456789', 'password123456789'
        ]

    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate a password according to NIST SP800-63B guidelines.
        Returns a tuple of (is_valid, error_message)
        """
        # Check length requirements
        if len(password) < self.min_length:
            return False, f"Password must be at least {self.min_length} characters long"
        
        if len(password) > self.max_length:
            return False, f"Password must not exceed {self.max_length} characters"

        # Check for common passwords using SHA-1 hash
        password_hash = hashlib.sha1(password.lower().encode()).hexdigest().upper()
        if password_hash in self.common_passwords:
            return False, "This password has been compromised in data breaches. Please choose a different one."

        # Check for common patterns
        if re.match(r'^[0-9]+$', password):
            return False, "Password cannot be all numbers"
        
        if re.match(r'^[a-zA-Z]+$', password):
            return False, "Password cannot be all letters"

        # Check for sequential characters
        if self._has_sequential_chars(password):
            return False, "Password contains too many sequential characters"

        return True, "Password meets requirements"

    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters in the password."""
        # Check for sequential numbers
        for i in range(len(password) - 2):
            if (password[i:i+3].isdigit() and 
                int(password[i:i+3]) in range(100, 999) and 
                int(password[i:i+3]) % 111 == 0):
                return True

        # Check for sequential letters
        for i in range(len(password) - 2):
            if (password[i:i+3].isalpha() and 
                ord(password[i+1]) - ord(password[i]) == 1 and 
                ord(password[i+2]) - ord(password[i+1]) == 1):
                return True

        return False 