# Crypto API indicators
CRYPTO_APIS = [
    "cryptencrypt",
    "cryptdecrypt",
    "aes",
    "rsa",
    "chacha20",
    "encrypt",
    "decrypt"
]

# File manipulation API indicators
FILE_APIS = [
    "createfile",
    "writefile",
    "deletefile",
    "findfirstfile",
    "findnextfile"
]

# Ransom note keywords
RANSOM_WORDS = [
    "bitcoin",
    "payment",
    "decrypt your files",
    "ransom",
    "wallet",
    "deadline"
]


def scan_keywords(file_path):
    """
    Scan file content for crypto APIs, file manipulation APIs, and ransom keywords.
    Returns tuple of (crypto_hits, file_api_hits, ransom_keyword_hits).
    """
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().lower()

        crypto_hits = sum(k in content for k in CRYPTO_APIS)
        file_hits = sum(k in content for k in FILE_APIS)
        ransom_hits = sum(k in content for k in RANSOM_WORDS)

        return crypto_hits, file_hits, ransom_hits

    except:
        return 0, 0, 0
