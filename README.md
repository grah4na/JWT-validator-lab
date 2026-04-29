# JWT-validator-lab


# JWT Attack Lab

A hands-on security project that demonstrates how JSON Web Tokens (JWTs) can be attacked and defended. This tool validates tokens, forges fake ones, cracks weak secrets, and detects key ID injection attempts.

---

## Why This Exists

I built this to learn JWT security from scratch. Instead of only reading theory, I implemented the attacks myself. Starting with no Python background, I ended up with a working security tool. You can follow the same path.

---

## Features

| Command       | Purpose                                                      |
|---------------|--------------------------------------------------------------|
| `validate`    | Verify JWT signatures and enforce allowed algorithms         |
| `forge-none`  | Generate an `alg:none` token with a custom payload            |
| `crack`       | Brute-force weak HMAC secrets using a wordlist                |
| `check-kid`   | Detect path traversal in the `kid` (key ID) header field      |

---

## Quick Start

### Requirements
- Python 3.8+
- pip

### Installation
```bash
git clone https://github.com/yourusername/jwt-attack-lab.git
cd jwt-attack-lab
pip install pyjwt

Usage Examples
Create a Test Token

bash
python -c "import jwt; print(jwt.encode({'user':'alice'}, 'secret123', algorithm='HS256'))"
Validate a Token

bash
python main.py validate "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.xyz123" "secret123"
Forge an alg:none Token

bash
python main.py forge-none "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.xyz123" '{"user":"admin"}'
Crack a Weak Secret

bash
echo "password123" > wordlist.txt
python main.py crack "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWxpY2UifQ.xyz123" wordlist.txt
Check for Key ID Injection

bash
python main.py check-kid "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.xyz123"
Project Structure
Code
jwt_attack_lab/
├── utils.py         # Base64URL + JSON helpers
├── validator.py     # JWT verification logic
├── attacker.py      # Attack implementations
├── main.py          # CLI entry point
├── tests/           # Sample tokens + wordlists
└── README.md



Attack Explanations
1. alg:none Attack
Some servers accept alg:none and skip signature checks.

Tool rewrites header to none, removes signature, returns forged token.

2. Weak Secret Cracking
HMAC JWTs rely on a shared secret.

Tool brute-forces secrets from a wordlist until signature matches.

3. Key ID Injection
kid header may be used as a file path.

Tool scans for suspicious patterns (../, /etc/, ..\) and flags them.

Core Concepts You’ll Learn
Base64URL: URL-safe encoding without padding

JSON: Compact representation of claims

SHA256: One-way hash function

HMAC: Keyed hash for authentication

Testing with jwt.io
Generate tokens with known secrets

Validate them using this tool

Try weak secrets and crack them

Create alg:none tokens and confirm rejection

A full testing guide is included in tests/.

Limitations
Supports only HS256

No expiration (exp, nbf) checks

No RS256/ES256 support

Kid detection is pattern-based only

Roadmap
RS256 verification + algorithm confusion attack

Expiration and audience claim validation

JWKS parsing

Automated scanner mode

Burp Suite extension

References
RFC 7519 – JWT Specification (datatracker.ietf.org in Bing)

PortSwigger Web Security Academy JWT labs

PyJWT documentation

Code

This version is concise, structured, and ready to drop into a GitHub repo as `README.md`
