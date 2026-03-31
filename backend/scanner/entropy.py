import math
from collections import Counter


def file_entropy(file_path):
    """
    Calculate Shannon entropy of file contents.
    Entropy interpretation:
    <4    → normal text/code
    4–6   → compiled or structured code
    >7    → encrypted or packed data
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0

        counter = Counter(data)
        length = len(data)

        entropy = 0

        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    except:
        return 0


def calculate_entropy(file_path):
    """
    Alias for file_entropy for backward compatibility.
    """
    return file_entropy(file_path)
