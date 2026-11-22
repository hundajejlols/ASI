"""
Application-level Encryption At Rest (AES-256-GCM) dla wrażliwych pól w PostgreSQL
(np. http_fingerprints.headers_encrypted, http_fingerprints.cookies_encrypted,
asset_overrides.notes_encrypted, integrations.api_token_encrypted).

Format binarny (BYTEA):
  [version: 1 bajt (0x01)] [nonce: 12 bajtów] [ciphertext + GCM tag (16 bajtów)]

Obsługuje AAD (Associated Authenticated Data) wiążące szyfrogram z kolumną/kontekstem,
z bezpiecznym fallbackiem przy odczycie starszych rekordów zaszyfrowanych bez AAD.
"""

import base64
import json
import logging
import os
from typing import Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings

logger = logging.getLogger(__name__)

CURRENT_VERSION = b"\x01"
NONCE_SIZE = 12
_WEAK_KEY_WARNED = False

# Stałe konteksty AAD dla kolumn szyfrowanych (chronią przed podmianą szyfrogramów między kolumnami)
AAD_HTTP_HEADERS = b"http_fingerprints.headers_encrypted"
AAD_HTTP_COOKIES = b"http_fingerprints.cookies_encrypted"
AAD_OVERRIDE_NOTES = b"asset_overrides.notes_encrypted"
AAD_INTEGRATION_TOKEN = b"integrations.api_token_encrypted"
AAD_AI_AGENT_KEY = b"ai_agent_configs.api_key_encrypted"


def _get_aesgcm() -> AESGCM:
    global _WEAK_KEY_WARNED
    raw_key = base64.b64decode(settings.encryption_master_key)
    if len(raw_key) != 32:
        raise ValueError("ENCRYPTION_MASTER_KEY musi mieć dokładnie 32 bajty (256 bitów) po zdekodowaniu Base64.")
    if raw_key == b"\x00" * 32:
        if not settings.allow_weak_encryption_key:
            raise RuntimeError(
                "BŁĄD BEZPIECZEŃSTWA: ENCRYPTION_MASTER_KEY ma wartość domyślną (32 bajty zerowe). "
                "Wygeneruj losowy 256-bitowy klucz Base64 w .env (lub ustaw ALLOW_WEAK_ENCRYPTION_KEY=true wyłącznie w dev)."
            )
        if not _WEAK_KEY_WARNED:
            _WEAK_KEY_WARNED = True
            logger.warning(
                "UWAGA BEZPIECZEŃSTWA: ENCRYPTION_MASTER_KEY ma wartość domyślną (32 bajty zerowe). "
                "Wygeneruj losowy klucz 256-bitowy w pliku .env przed wdrożeniem!"
            )
    return AESGCM(raw_key)


def validate_master_key() -> None:
    """Waliduje klucz ENCRYPTION_MASTER_KEY przy starcie aplikacji."""
    _get_aesgcm()


def encrypt_field(plaintext: str, associated_data: bytes | None = None) -> bytes:
    """Szyfruje tekst jawny za pomocą AES-256-GCM z opcjonalnym AAD."""
    aesgcm = _get_aesgcm()
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
    return CURRENT_VERSION + nonce + ciphertext


def decrypt_field(
    blob: bytes,
    associated_data: bytes | None = None,
    *,
    allow_legacy_no_aad: bool = True,
) -> str:
    """Deszyfruje pole BYTEA zaszyfrowane przez encrypt_field."""
    if not blob or len(blob) < 1 + NONCE_SIZE + 16:
        raise ValueError("Nieprawidłowy format zaszyfrowanego pola.")
    version = blob[:1]
    if version != CURRENT_VERSION:
        raise ValueError(f"Nieobsługiwana wersja szyfrowania: {version!r}")
    nonce = blob[1 : 1 + NONCE_SIZE]
    ciphertext = blob[1 + NONCE_SIZE :]
    aesgcm = _get_aesgcm()
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception:
        if associated_data is not None and allow_legacy_no_aad:
            # Zgodność wsteczna dla rekordów zaszyfrowanych przed wprowadzeniem AAD
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        else:
            raise
    return plaintext.decode("utf-8")


def decrypt_field_safe(
    blob: bytes | None,
    default: str | None = None,
    associated_data: bytes | None = None,
) -> str | None:
    """Bezpiecznie deszyfruje pole BYTEA; zwraca default dla None lub przy niezgodnym kluczu (InvalidTag)."""
    if not blob:
        return default
    try:
        return decrypt_field(bytes(blob), associated_data=associated_data)
    except Exception:
        return default


def encrypt_json(data: Any, associated_data: bytes | None = None) -> bytes:
    """Serializuje obiekt do JSON i szyfruje za pomocą AES-256-GCM."""
    serialized = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return encrypt_field(serialized, associated_data=associated_data)


def decrypt_json(blob: bytes | None, default: Any = None, associated_data: bytes | None = None) -> Any:
    """Deszyfruje pole BYTEA i parsuje JSON; zwraca default dla None lub przy błędzie klucza."""
    if not blob:
        return default
    try:
        raw = decrypt_field(bytes(blob), associated_data=associated_data)
        return json.loads(raw)
    except Exception:
        return default
