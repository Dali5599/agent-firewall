import math
from typing import List, Tuple


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a given string.

    Higher entropy typically indicates random or encrypted data,
    such as API keys, tokens, or hashes.

    Args:
        data: The input string to analyze.

    Returns:
        float: The Shannon entropy value (bits per character).
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    
    # Count frequencies of each character
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    # Calculate Shannon entropy: - sum( p(x) * log2(p(x)) )
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def detect_high_entropy_strings(
    text: str,
    min_length: int = 16,
    max_length: int = 128,
    threshold: float = 4.5,
    word_boundary_check: bool = True
) -> List[Tuple[str, int, int, float]]:
    """Scan a block of text for substrings that exhibit high Shannon entropy,
    which often correspond to leaked secrets, API keys, or tokens.

    Args:
        text: The source text to scan.
        min_length: Minimum length of substrings to evaluate.
        max_length: Maximum length of substrings to evaluate.
        threshold: Entropy threshold above which a substring is flagged.
        word_boundary_check: If True, evaluates space-delimited tokens.

    Returns:
        List[Tuple[str, int, int, float]]: A list of detected secrets represented as
        tuples of (substring, start_index, end_index, entropy_score).
    """
    findings: List[Tuple[str, int, int, float]] = []
    
    if not text or len(text) < min_length:
        return findings

    if word_boundary_check:
        # Split text by whitespace and punctuation boundaries while tracking absolute offsets
        tokens = []
        current_token = ""
        current_start = 0

        for i, char in enumerate(text):
            if char.isspace() or char in "\"'`()[]{}<>.,;:!?\\/|":
                if current_token:
                    tokens.append((current_token, current_start, i))
                    current_token = ""
                current_start = i + 1
            else:
                if not current_token:
                    current_start = i
                current_token += char

        if current_token:
            tokens.append((current_token, current_start, len(text)))

        for token, start, end in tokens:
            token_len = len(token)
            if min_length <= token_len <= max_length:
                score = calculate_shannon_entropy(token)
                if score >= threshold:
                    findings.append((token, start, end, score))
    else:
        # Sliding window approach for continuous dense strings
        step = 1
        for length in range(min_length, min(max_length + 1, len(text) + 1)):
            for i in range(0, len(text) - length + 1):
                substring = text[i : i + length]
                score = calculate_shannon_entropy(substring)
                if score >= threshold:
                    findings.append((substring, i, i + length, score))

    return findings
