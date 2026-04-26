#!/usr/bin/env python3
import sys
import json
from validator import validate_jwt
from attacker import forge_none_token, crack_hs256_secret, check_suspicious_kid

def print_help():
    print("""
JWT Attack Lab - Usage:
    python main.py validate <token> <secret>
    python main.py forge-none <token> '<json_payload>'
    python main.py crack <token> <wordlist_file>
    python main.py check-kid <token>
    python main.py help

Examples:
    python main.py validate "eyJ..." "mysecret"
    python main.py forge-none "eyJ..." '{"admin":true}'
    python main.py crack "eyJ..." passwords.txt
    python main.py check-kid "eyJ..."
""")

def main():
    if len(sys.argv) < 2:
        print_help()
        return
    
    command = sys.argv[1]
    
    if command == "validate" and len(sys.argv) == 4:
        token = sys.argv[2]
        secret = sys.argv[3].encode()
        valid, header, payload, msg = validate_jwt(token, secret)
        print(f"Valid: {valid}")
        print(f"Message: {msg}")
        if header:
            print(f"Header: {json.dumps(header, indent=2)}")
            print(f"Payload: {json.dumps(payload, indent=2)}")
    
    elif command == "forge-none" and len(sys.argv) == 4:
        token = sys.argv[2]
        payload = json.loads(sys.argv[3])
        forged = forge_none_token(token, payload)
        print(f"Forged token:\n{forged}")
    
    elif command == "crack" and len(sys.argv) == 4:
        token = sys.argv[2]
        wordlist = sys.argv[3]
        secret = crack_hs256_secret(token, wordlist)
        if secret:
            print(f"✅ Secret found: {secret}")
        else:
            print("❌ Secret not found in wordlist")
    
    elif command == "check-kid" and len(sys.argv) == 3:
        token = sys.argv[2]
        suspicious, msg = check_suspicious_kid(token)
        print(f"Suspicious: {suspicious}")
        print(f"Reason: {msg}")
    
    else:
        print_help()

if __name__ == "__main__":
    main()