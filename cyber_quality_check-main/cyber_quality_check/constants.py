import re

LEAK_TERMS = [
    "idor", "bola", "sqli", "sql injection", "ssrf", "xxe", "traversal",
    "path traversal", "directory traversal", "mass assignment",
    "massassign", "ssti", "xss", "cross-site scripting", "rce",
    "remote code execution", "csrf", "lfi", "rfi", "deserializ",
    "command injection", "cmdi", "broken access control", "privilege escalation",
    "authentication bypass", "authbypass",
]

CSPRNG_RE = re.compile(r"secrets\.token|os\.urandom|token_hex|/dev/urandom|openssl rand|SystemRandom", re.I)
FLAG_PREFIX_RE = re.compile(r"\b([A-Z0-9_]*FLAG[A-Z0-9_]*)\s*=", re.MULTILINE)
PRIVATE_RANGE_RE = re.compile(r"172\.16\.0\.0/12|10\.0\.0\.0/8|192\.168\.0\.0/16")
DIGEST_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}")
FROM_IMAGE_RE = re.compile(r"^\s*FROM\s+(\S+)", re.MULTILINE | re.IGNORECASE)
COMPOSE_IMAGE_RE = re.compile(r"^\s*image:\s*(\S+)", re.MULTILINE)
SUBNET_LITERAL_RE = re.compile(r"(subnet|ipv4_address):\s*[\"']?(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)", re.I)
SHORTCUT_PATH_RE = re.compile(r"\.env(?!iron)\b|seed_data|config\.(py|json|ya?ml)|/etc/passwd")

APP_SOURCE_EXTENSIONS = (
    ".py", ".php", ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".java", ".cs",
)
