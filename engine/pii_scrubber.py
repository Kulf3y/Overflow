import re
from typing import Tuple, Dict


class PIIScrubber:
    """Locally sanitizes common PII using regex-based pattern matching."""

    PATTERNS = {
        "EMAIL": re.compile(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        ),

        "PHONE_EU": re.compile(
            r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?"
            r"(?:\(?\d{2,4}\)?[\s.-]?)"
            r"\d{3,4}[\s.-]?\d{3,4}(?!\d)"
        ),

        "IBAN": re.compile(
            r"\b[A-Z]{2}\d{2}(?:[A-Z0-9][\s-]?){11,30}\b",
            re.IGNORECASE
        ),

        "CREDIT_CARD": re.compile(
            r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"
        ),

        "CNP_ROMANIA": re.compile(
            r"\b[1-8]\d{2}"
            r"(?:0[1-9]|1[0-2])"
            r"(?:0[1-9]|[12]\d|3[01])"
            r"\d{6}\b"
        ),
    }

    def sanitize(self, text: str) -> Tuple[str, Dict[str, int]]:
        sanitized_text = text
        stats: Dict[str, int] = {}

        for pii_type, pattern in self.PATTERNS.items():
            sanitized_text, count = pattern.subn(
                f"[{pii_type}_REDACTED]",
                sanitized_text
            )

            if count:
                stats[pii_type] = count

        return sanitized_text, stats


if __name__ == "__main__":
    scrubber = PIIScrubber()

    sample = (
        "Contact John at john.doe@euprivacy.eu "
        "or +40721123456 with IBAN "
        "RO49AAAA1B31007593840000"
    )

    clean, report = scrubber.sanitize(sample)

    print("Clean Output:", clean)
    print("Redactions:", report)
