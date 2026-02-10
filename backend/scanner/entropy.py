import math
from collections import Counter

def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if not data:
            return 0.0
        counter = Counter(data)
        entropy = -sum(
            (count / len(data)) * math.log2(count / len(data))
            for count in counter.values()
        )
        return round(entropy, 2)
    except:
        return 0.0
