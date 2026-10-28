import hmac

from ..config import settings


def fingerprint_access_granted(code: str | None) -> bool:
    expected = settings.fingerprint_reveal_code
    return bool(code and expected) and hmac.compare_digest(code, expected)
