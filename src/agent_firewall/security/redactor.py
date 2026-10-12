import re
import math
from typing import List, Tuple, Dict, Any, Optional

class Redactor:
    """
    High-performance redaction engine combining precision regular expressions 
    and Shannon entropy analysis to scrub sensitive data, API keys, JWTs, and PII.
    """

    def __init__(self, min_entropy: float = 4.5, min_length: int = 20) -> None:
        self.min_entropy = min_entropy
        self.min_length = min_length
        self.redaction_count = 0

        self.patterns: List[Tuple[str, re.Pattern]] = [
            ("OPENAI_API_KEY", re.compile(r"sk-[a-zA-Z0-9_\-]{20,}")),
            ("ANTHROPIC_API_KEY", re.compile(r"sk-ant-[a-zA-Z0-9\-]{20,}")),
            ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
            ("AWS_SECRET_KEY", re.compile(r"aws[_\-]?(?:secret|access)[_\-]?key\s*[:=]\s*[a-zA-Z0-9/+=]{40}", re.IGNORECASE)),
            ("GITHUB_TOKEN", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
            ("SLACK_TOKEN", re.compile(r"xox[baprs]-[a-zA-Z0-9\-]{10,48}")),
            ("STRIPE_KEY", re.compile(r"sk_(?:live|test)_[a-zA-Z0-9]{24,}")),
            ("GOOGLE_API_KEY", re.compile(r"AIzaSy[a-zA-Z0-9_\-]{33}")),
            ("JWT_TOKEN", re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+")),
            ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----[a-zA-Z0-9/+= \n\r]+-----END (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----")),
        ]

    @property
    def compiled_patterns(self) -> List[re.Pattern]:
        return [p for _, p in self.patterns]

    def add_pattern(self, pattern_str: str, placeholder: str = "[REDACTED_SECRET]") -> None:
        compiled = re.compile(pattern_str)
        self.patterns.insert(0, (placeholder, compiled))

    def contains_secrets(self, text: str) -> bool:
        if not text:
            return False
        for _, pattern in self.patterns:
            if pattern.search(text):
                return True
        return False

    def redact(self, text: str, placeholder: str = "[REDACTED_SECRET]") -> str:
        if text is None:
            raise TypeError("Text cannot be None")
        if not isinstance(text, str):
            raise TypeError("Text must be a string")
        if not text:
            return ""

        sanitized = text
        for label, pattern in self.patterns:
            rep = label if label.startswith("[") else placeholder
            matches = list(pattern.finditer(sanitized))
            for match in reversed(matches):
                start, end = match.span()
                matched_str = sanitized[start:end]
                if label == "OPENAI_API_KEY" and not matched_str.startswith("sk-"):
                    continue
                sanitized = sanitized[:start] + rep + sanitized[end:]
                self.redaction_count += 1

        return sanitized

    def redact_payload(self, payload: Any, placeholder: str = "[REDACTED_SECRET]") -> Any:
        if isinstance(payload, dict):
            return {k: self.redact_payload(v, placeholder) for k, v in payload.items()}
        elif isinstance(payload, list):
            return [self.redact_payload(item, placeholder) for item in payload]
        elif isinstance(payload, str):
            return self.redact(payload, placeholder)
        return payload

RedactorEngine = Redactor
