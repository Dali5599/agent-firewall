import re
from typing import List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class BashGuardResult:
    is_safe: bool
    blocked_reason: Optional[str] = None
    matched_rule: Optional[str] = None

GuardResult = BashGuardResult

class BashGuard:
    """
    Security inspection engine for scanning tool payloads and bash commands
    for destructive system actions, unauthorized access, and dangerous operations.
    """

    SAFE_ALLOWLIST = [
        re.compile(r"^rm\s+-[rfR]+\s+\./node_modules", re.IGNORECASE),
        re.compile(r"^rm\s+-[rfR]+\s+node_modules", re.IGNORECASE)
    ]

    DANGEROUS_PATTERNS: List[Tuple[str, str]] = [
        (r"\bmkfs(\.[a-z0-9]+)?\s+", "Raw disk formatting"),
        (r"\bfdisk\s+", "Disk partitioning tampering"),
        (r"\bdd\s+.*of=/dev/(sd[a-z]|mem|null|zero)", "Raw device write via dd"),
        (r">\s*/dev/(sd[a-z]|mem)", "Direct device overwrite"),
        (r":\(\)\s*\{\s*:\|:&\s*\};:", "Classic bash fork bomb"),
        (r"\(\)\{:\|:&\};:", "Bash fork bomb variant"),
        (r"[a-zA-Z0-9_]+\(\)\s*\{\s*[a-zA-Z0-9_]+\s*\|\s*[a-zA-Z0-9_]+\s*&\s*\};", "Custom function fork bomb"),
        (r"\bchmod\s+-[rR]?\s*777\s+/", "Dangerous global permission escalation on /"),
        (r"\bchmod\s+000\s+/etc/shadow", "Shadow file lock tampering"),
        (r"\bchown\s+.*-R.*(\s+/|\s+nobody)", "Recursive ownership tampering on root"),
        (r"\bchmod\s+(u\+s|4755)\s+", "Dangerous SUID bit tampering"),
        (r"\bcurl\s+.*\|\s*(bash|sh)\b", "Dangerous remote script execution via pipe"),
        (r"\bwget\s+.*\|\s*(bash|sh|python3)\b", "Dangerous remote script execution via pipe"),
        (r"\biptables\s+-[FX]", "Firewall rule flush"),
        (r"\bufw\s+disable", "Firewall disable"),
        (r"\bhistory\s+-c", "History wipe"),
        (r"rm\s+.*(bash_history|zsh_history)", "Shell history deletion"),
        (r">\s*~?/\.(bash_history|zsh_history)", "Shell history truncation"),
        (r"systemctl\s+(stop|disable)\s+(firewalld|auditd)", "Security service disablement"),
    ]

    def __init__(self) -> None:
        self.custom_rules: List[Tuple[str, str]] = []

    def add_blacklist_rule(self, keyword_or_regex: str, reason: str) -> None:
        self.custom_rules.append((keyword_or_regex, reason))

    def validate(self, command: str) -> BashGuardResult:
        if not command or not command.strip():
            return BashGuardResult(is_safe=True)

        cmd = command.strip()

        # Check safe allowlist
        for allow in self.SAFE_ALLOWLIST:
            if allow.search(cmd):
                return BashGuardResult(is_safe=True)

        # Check custom rules
        for pattern_str, reason in self.custom_rules:
            if pattern_str in cmd or re.search(re.escape(pattern_str), cmd):
                return BashGuardResult(is_safe=False, blocked_reason=reason, matched_rule=pattern_str)

        # Destructive rm commands targeting system directories
        if re.search(r"(?:sudo\s+)?rm\s+.*(?:-[a-zA-Z]*[rfR]|[rfR]).*(?:/|~|passwd|var|bin|usr)", cmd, re.IGNORECASE) or "rm -rf /" in cmd or "rm -f /etc" in cmd:
            return BashGuardResult(is_safe=False, blocked_reason="Destructive rm command targeting system", matched_rule="rm")

        # Obfuscation
        if "base64" in cmd or "eval" in cmd:
            return BashGuardResult(is_safe=False, blocked_reason="Obfuscated base64 or eval command", matched_rule="obfuscation")

        # Crontab manipulation
        if "crontab" in cmd:
            return BashGuardResult(is_safe=False, blocked_reason="Crontab manipulation", matched_rule="crontab")

        # Python one-liner destructive attacks
        if "python" in cmd and "rm" in cmd and "-rf" in cmd:
            return BashGuardResult(is_safe=False, blocked_reason="Python destructive command", matched_rule="python_exec")

        # Check dangerous patterns
        for pattern_str, reason in self.DANGEROUS_PATTERNS:
            if re.search(pattern_str, cmd, re.IGNORECASE | re.MULTILINE):
                return BashGuardResult(is_safe=False, blocked_reason=reason, matched_rule=pattern_str)

        return BashGuardResult(is_safe=True)
