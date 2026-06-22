from mnemonic import Mnemonic

mnemo = Mnemonic("english")

def private_key_to_mnemonic(private_key_bytes: bytes) -> str:
    if len(private_key_bytes) != 32:
        raise ValueError(f"Expected 32 bytes, got {len(private_key_bytes)}")

    return mnemo.to_mnemonic(private_key_bytes)

def mnemonic_to_private_key(phrase: str) -> bytes:
    phrase = phrase.strip().lower()

    if not mnemo.check(phrase):
        raise ValueError("Invalid mnemonic phrase.")

    entropy = mnemo.to_entropy(phrase)

    if len(entropy) != 32:
        raise ValueError(f"Expected 32 bytes of entropy, got {len(entropy)}")

    return bytes(entropy)

def format_mnemonic_display(phrase: str) -> str:
    words = phrase.split()
    lines = []
    for i in range(0, len(words), 4):
        row = "   ".join(
            f"{str(j + 1).zfill(2)}. {words[j]:<12}"
            for j in range(i, min(i + 4, len(words)))
        )
        lines.append(row)
    return "\n".join(lines)
