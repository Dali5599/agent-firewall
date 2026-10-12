import re
from typing import Dict, Pattern

PATTERNS: Dict[str, Pattern[str]] = {
    "openai_api_key": re.compile(r"sk-[a-zA-Z0-9]{20,48}T3BlbkFJ[a-zA-Z0-9]{20,48}|sk-[a-zA-Z0-9]{48}"),
    "anthropic_api_key": re.compile(r"sk-ant-api03-[a-zA-Z0-9\-_]{93}AA"),
    "aws_access_key": re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "github_pat": re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "github_oauth": re.compile(r"gho_[a-zA-Z0-9]{36}"),
    "github_refresh": re.compile(r"ghr_[a-zA-Z0-9]{36,76}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED )?PRIVATE KEY-----\n[a-zA-Z0-9/+= \n]+\n-----END (?:RSA|DSA|EC|OPENSSH|ENCRYPTED )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+"),
    "generic_secret": re.compile(r"(?:api[_-]?key|secret|token|password|auth|credential)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9\-_/.]{16,64})['\"]", re.IGNORECASE),
}

DESTRUCTIVE_BASH_PATTERNS: Dict[str, Pattern[str]] = {
    "rm_rf_root": re.compile(r"rm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|f[a-zA-Z]*r[a-zA-Z]*)\s+/(?:\s|$|*)"),
    "mkfs": re.compile(r"mkfs(?:\.[a-z]+)?\s+/dev/"),
    "dd_disk": re.compile(r"dd\s+if=.*?\s+of=/dev/sd[a-z]"),
    "fork_bomb": re.compile(r":\s*\{\s*:\s*\|\s*:\s*&\s*\};?\s*"),
    "chmod_recursive_root": re.compile(r"chmod\s+-[Rr]\s+777\s+/(?:\s|$|*)"),
    "wget_curl_pipe_sh": re.compile(r"(?:wget|curl)\s+.*?\|\s*(?:sudo\s+)?(?:bash|sh)"),
}
