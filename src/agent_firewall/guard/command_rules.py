import re
from typing import List, Pattern, Tuple

# Compiled regex patterns for detecting destructive or unauthorized system commands
# Target environments: Linux/Unix shells, SQL databases, Python execution, and file manipulation.

DESTRUCTIVE_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    (
        "rm_recursive_force",
        re.compile(r"\brm\s+(?:-[rfiv]*[rf][rfiv]*\s+)+[/~]", re.IGNORECASE)
    ),
    (
        "rm_root_or_home",
        re.compile(r"\brm\s+.*(?:/[^/\s]+)*\s*(?:/|~|\$HOME)\b", re.IGNORECASE)
    ),
    (
        "mkfs_command",
        re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\s+", re.IGNORECASE)
    ),
    (
        "dd_destructive",
        re.compile(r"\bdd\s+.*\bof=/dev/[hd]?[a-z]+", re.IGNORECASE)
    ),
    (
        "fork_bomb",
        re.compile(r":\s*\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\};\s*:", re.IGNORECASE)
    ),
    (
        "sql_drop_table",
        re.compile(r"\bDROP\s+(?:DATABASE|TABLE|SCHEMA)\b", re.IGNORECASE)
    ),
    (
        "sql_truncate",
        re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?\w+", re.IGNORECASE)
    ),
    (
        "sql_dangerous_exec",
        re.compile(r"\bEXEC(?:UTE)?\s*\(\s*['\"].*?\b(?:SHUTDOWN|XP_CMDSHELL)\b", re.IGNORECASE)
    ),
    (
        "chmod_dangerous",
        re.compile(r"\bchmod\s+(?:-R\s+)?[0-7]{3,4}\s+[/~]", re.IGNORECASE)
    ),
    (
        "pipe_to_shell",
        re.compile(r"\b(?:curl|wget)\s+[^|]+\|\s*(?:bash|sh|zsh|python\d*)", re.IGNORECASE)
    ),
    (
        "system_shutdown_reboot",
        re.compile(r"\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b", re.IGNORECASE)
    ),
    (
        "iptables_flush",
        re.compile(r"\biptables\s+(?:-[FfXZ]|--flush)\b", re.IGNORECASE)
    ),
    (
        "dev_null_overwrite",
        re.compile(r">\s*/dev/sd[a-z]\d*", re.IGNORECASE)
    ),
]


def check_command_safety(command: str) -> Tuple[bool, str]:
    """
    Analyzes a given command string against known dangerous patterns.
    
    Args:
        command (str): The command or tool argument string to inspect.
        
    Returns:
        Tuple[bool, str]: A tuple where the first element is True if the command 
                          is safe (no matches), or False if blocked. The second 
                          element is a description of the triggered rule or "SAFE".
    """
    if not isinstance(command, str) or not command.strip():
        return True, "SAFE"

    for rule_name, pattern in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            return False, f"Blocked by rule: {rule_name}"

    return True, "SAFE"


def get_all_rules() -> List[str]:
    """
    Retrieves the identifiers of all active command security rules.
    
    Returns:
        List[str]: List of rule names.
    """
    return [rule_name for rule_name, _ in DESTRUCTIVE_PATTERNS]
