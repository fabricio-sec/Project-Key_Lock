import math
import re
import string

_LEET_RE = re.compile(r"[4@][a-z]|[3][e]|[1!][il]|[0][o]|[$5][s]", re.I)
_YEAR_RE  = re.compile(r"(19|20)\d{2}")
_COMMON_SUFFIX_RE = re.compile(r"[!@#$%^&*]{1,2}$")

_DICEWARE_BITS_PER_WORD = 10.5

def estimate_passphrase_entropy(passphrase: str, machine_generated: bool = False) -> dict:
    warnings_list = []
    charset_size = 0

    has_lower  = any(c in string.ascii_lowercase for c in passphrase)
    has_upper  = any(c in string.ascii_uppercase for c in passphrase)
    has_digit  = any(c.isdigit() for c in passphrase)
    has_symbol = any(c in string.punctuation for c in passphrase)

    if has_lower:  charset_size += 26
    if has_upper:  charset_size += 26
    if has_digit:  charset_size += 10
    if has_symbol: charset_size += 32
    if " " in passphrase: charset_size += 1

    if charset_size == 0:
        charset_size = 26

    charset_bits = len(passphrase) * math.log2(charset_size)
    word_count = len(passphrase.split())

    penalty = 1.0

    if not machine_generated:
        if len(passphrase) < 15:
            warnings_list.append("Muito curta — use pelo menos 20 caracteres")
            penalty *= 0.55

        if _LEET_RE.search(passphrase):
            penalty *= 0.75
            warnings_list.append("Substituições l33t (@, $, 3…) reduzem entropia real")

        if _YEAR_RE.search(passphrase):
            penalty *= 0.85
            warnings_list.append("Anos (19xx / 20xx) são previsíveis — evite ou combine com mais aleatoriedade")

        if _COMMON_SUFFIX_RE.search(passphrase) and not has_symbol:
            penalty *= 0.9

    charset_bits *= penalty

    estimates = [charset_bits]
    if word_count >= 4:
        diceware_bits = word_count * _DICEWARE_BITS_PER_WORD
        estimates.append(diceware_bits)
    elif not machine_generated:
        warnings_list.append("Use pelo menos 4 palavras para frases mais seguras")

    if not machine_generated and not has_digit and not has_symbol:
        warnings_list.append("Adicione números ou símbolos (ex: !@# ou anos)")

    entropy_bits = min(estimates)

    if entropy_bits < 40:
        strength = "fraca ❌"
    elif entropy_bits < 60:
        strength = "razoável ⚠️"
    elif entropy_bits < 80:
        strength = "boa ✅"
    else:
        strength = "forte 💪"

    return {
        "bits": round(entropy_bits, 1),
        "strength": strength,
        "warnings": warnings_list,
        "word_count": word_count,
    }

def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    import secrets

    charset = string.ascii_lowercase
    required = []

    if use_upper:
        charset += string.ascii_uppercase
        required.append(string.ascii_uppercase)
    if use_digits:
        charset += string.digits
        required.append(string.digits)
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        charset += symbols
        required.append(symbols)

    while True:
        pwd = [secrets.choice(charset) for _ in range(length)]
        if all(any(c in cat for c in pwd) for cat in required):
            return "".join(pwd)
