# JWT Attack Lab
 
A hands-on security tool that demonstrates real-world JWT vulnerabilities — validate tokens, forge signatures, crack weak secrets, and detect key ID injection attacks.
 
---
 
## Why This Exists
 
JWT security is best learned by breaking things. This lab implements the attacks directly rather than just reading theory — giving you a working tool and deep intuition for how JWTs can go wrong.
 
---
 
## Features
 
| Command      | What It Does                                              |
|--------------|-----------------------------------------------------------|
| `validate`   | Verify JWT signatures and enforce allowed algorithms      |
| `forge-none` | Generate an `alg:none` token with a custom payload        |
| `crack`      | Brute-force weak HMAC secrets using a wordlist            |
| `check-kid`  | Detect path traversal attempts in the `kid` header field  |
 
---
 
## Installation
 
**Requirements:** Python 3.8+
 
```bash
git clone https://github.com/yourusername/jwt-attack-lab.git
cd jwt-attack-lab
pip install pyjwt
```
 
---
 
## Usage
 
### Create a test token
```bash
python -c "import jwt; print(jwt.encode({'user':'alice'}, 'secret123', algorithm='HS256'))"
```
 
### Validate a token
```bash
python main.py validate "<token>" "secret123"
```
 
### Forge an alg:none token
```bash
python main.py forge-none "<token>" '{"user":"admin"}'
```
 
### Crack a weak secret
```bash
echo "password123" > wordlist.txt
python main.py crack "<token>" wordlist.txt
```
 
### Check for key ID injection
```bash
python main.py check-kid "<token_with_suspicious_kid>"
```
 
---
 
## Project Structure
 
```
jwt_attack_lab/
├── main.py          # CLI entry point
├── validator.py     # JWT verification logic
├── attacker.py      # Attack implementations
├── utils.py         # Base64URL + JSON helpers
├── tests/           # Sample tokens and wordlists
└── README.md
```
 
---
 
## Attack Explanations
 
### 1. `alg:none` Attack
Some servers blindly accept `alg:none` and skip signature verification entirely. This tool rewrites the header algorithm to `none`, strips the signature, and returns a forged token accepted by vulnerable servers.
 
### 2. Weak Secret Cracking
HMAC-signed JWTs (`HS256`) are only as strong as their secret. Given a wordlist, this tool recomputes the signature for each candidate and flags the match — exposing how easily guessable secrets compromise the entire token.
 
### 3. Key ID (`kid`) Injection
The `kid` header field is sometimes passed directly into file path lookups. This tool scans for path traversal patterns (`../`, `/etc/`, `..\`) in the `kid` value and flags suspicious tokens before they reach your verification logic.
 
---
 
## Core Concepts
 
| Concept    | Role in JWTs                                  |
|------------|-----------------------------------------------|
| Base64URL  | URL-safe encoding used for header and payload |
| JSON       | Compact key-value structure for claims        |
| SHA-256    | One-way hash function underlying HMAC         |
| HMAC       | Keyed hash that authenticates the signature   |
 
---
 
## Testing with jwt.io
 
1. Generate a token with a known secret
2. Validate it using this tool
3. Try weak secrets — then crack them
4. Create an `alg:none` token and confirm it gets rejected
A full testing walkthrough is in `tests/`.
 
---
 
## Current Limitations
 
- Supports HS256 only
- No expiration (`exp`, `nbf`) or audience (`aud`) validation
- No RS256 / ES256 support
- `kid` detection is pattern-based, not structural
---
 
## Roadmap
 
- [ ] RS256 verification + algorithm confusion attack
- [ ] Expiration and audience claim validation
- [ ] JWKS endpoint parsing
- [ ] Automated scanner mode
- [ ] Burp Suite extension
---
 
## References
 
- [RFC 7519 — JWT Specification](https://datatracker.ietf.org/doc/html/rfc7519)
- [PortSwigger Web Security Academy — JWT Labs](https://portswigger.net/web-security/jwt)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
