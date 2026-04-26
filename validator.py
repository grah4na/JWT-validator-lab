import hmac
import hashlib
from utils import split_jwt, decode_jwt_part, b64url_decode

ALLOWED_ALGORITHMS = ["HS256"]  # Only accept HS256

def verify_signature(token, secret_bytes):
    """Check if HMAC signature is correct"""
    # Split token
    header_b64, payload_b64, sig_b64 = split_jwt(token)
    
    # Recreate what was signed
    message = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    # Compute expected signature
    expected_sig = hmac.new(secret_bytes, message, hashlib.sha256).digest()
    
    # Get provided signature
    provided_sig = b64url_decode(sig_b64)
    
    # Compare safely
    return hmac.compare_digest(expected_sig, provided_sig)

def validate_jwt(token, secret_bytes):
    """Full JWT validation"""
    try:
        # Split and decode
        header_b64, payload_b64, sig_b64 = split_jwt(token)
        header = decode_jwt_part(header_b64)
        payload = decode_jwt_part(payload_b64)
        
        # Check 1: Algorithm must be allowed
        alg = header.get("alg", "")
        if alg not in ALLOWED_ALGORITHMS:
            return False, header, payload, f"Forbidden algorithm: {alg}"
        
        # Check 2: Signature must be valid
        if not verify_signature(token, secret_bytes):
            return False, header, payload, "Invalid signature"
        
        # All checks passed
        return True, header, payload, "Valid token"
        
    except Exception as e:
        return False, {}, {}, f"Error: {str(e)}"

# Test it
if __name__ == "__main__":
    # Create a test token (requires PyJWT - install with: pip install pyjwt)
    import jwt
    test_token = jwt.encode({"user": "alice"}, "secret123", algorithm="HS256")
    print(f"Test token: {test_token}")
    
    # Validate with correct secret
    valid, header, payload, msg = validate_jwt(test_token, b"secret123")
    print(f"Correct secret: {msg}")
    print(f"Header: {header}")
    print(f"Payload: {payload}")
    
    # Validate with wrong secret
    valid, header, payload, msg = validate_jwt(test_token, b"wrong")
    print(f"\nWrong secret: {msg}")