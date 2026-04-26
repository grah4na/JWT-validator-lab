import base64
import json

def b64url_encode(data):
    """Convert bytes to base64url (no padding)"""
    # Step 1: Normal base64 encode
    normal_b64 = base64.b64encode(data)
    # Step 2: Convert to string
    b64_str = normal_b64.decode()
    # Step 3: Remove padding (=) and replace +/ with -_
    b64url = b64_str.rstrip("=").replace("+", "-").replace("/", "_")
    return b64url

def b64url_decode(data):
    """Convert base64url string back to bytes"""
    # Step 1: Add back padding
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    # Step 2: Replace -_ back to +/
    data = data.replace("-", "+").replace("_", "/")
    # Step 3: Decode
    return base64.b64decode(data)

def encode_jwt_part(obj):
    """Convert dict to JWT part (JSON -> bytes -> base64url)"""
    json_str = json.dumps(obj, separators=(',', ':'))
    json_bytes = json_str.encode('utf-8')
    return b64url_encode(json_bytes)

def decode_jwt_part(part):
    """Convert JWT part back to dict"""
    json_bytes = b64url_decode(part)
    json_str = json_bytes.decode('utf-8')
    return json.loads(json_str)

def split_jwt(token):
    """Split JWT into three parts"""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT: wrong number of parts")
    return parts[0], parts[1], parts[2]