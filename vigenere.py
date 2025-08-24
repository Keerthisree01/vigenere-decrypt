import re
from collections import Counter
from spellchecker import SpellChecker

def vigenere_encrypt(plaintext, keyword):
    ciphertext = []
    keyword = keyword.upper()
    plaintext = plaintext.upper()
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]  
    for p, k in zip(plaintext, keyword_repeated):
        if p.isalpha():
            shift = ord(k) - ord('A')
            encrypted_char = chr((ord(p) - ord('A') + shift) % 26 + ord('A'))
            ciphertext.append(encrypted_char)
        else:
            ciphertext.append(p)
    return ''.join(ciphertext)

def vigenere_decrypt(ciphertext, keyword):
    plaintext = []
    keyword = keyword.upper()
    ciphertext = ciphertext.upper()
    keyword_repeated = (keyword * (len(ciphertext) // len(keyword) + 1))[:len(ciphertext)]  
    for c, k in zip(ciphertext, keyword_repeated):
        if c.isalpha():
            shift = ord(k) - ord('A')
            decrypted_char = chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
            plaintext.append(decrypted_char)
        else:
            plaintext.append(c)
    return ''.join(plaintext)

ENGLISH_FREQ = {
    'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
    'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
    'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
    'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
    'Q': 0.1, 'Z': 0.07
}

def chi_squared_stat(text):
    text = re.sub(r'[^A-Z]', '', text.upper())
    if not text:
        return float("inf")
    count = Counter(text)
    total = sum(count.values())
    chi2 = 0
    for letter in ENGLISH_FREQ:
        observed = count.get(letter, 0)
        expected = ENGLISH_FREQ[letter] * total / 100
        chi2 += (observed - expected) ** 2 / (expected + 1e-6)
    return chi2

def guess_caesar_shift(text):
    best_shift, best_chi2 = 0, float("inf")
    for shift in range(26):
        decrypted = ''.join(
            chr((ord(c) - ord('A') - shift) % 26 + ord('A')) if c.isalpha() else c
            for c in text.upper()
        )
        chi2 = chi_squared_stat(decrypted)
        if chi2 < best_chi2:
            best_shift, best_chi2 = shift, chi2
    return best_shift

def auto_vigenere_decrypt(ciphertext, max_keylen=10):
    ciphertext = ciphertext.upper()
    best_score, best_plain, best_key = float("inf"), "", ""
    for keylen in range(1, max_keylen + 1):
        key_shifts = []
        for i in range(keylen):
            col = ciphertext[i::keylen]
            if col.strip():
                shift = guess_caesar_shift(col)
                key_shifts.append(shift)
            else:
                key_shifts.append(0)
        keyword = ''.join(chr(s + ord('A')) for s in key_shifts)
        plain = vigenere_decrypt(ciphertext, keyword)
        score = chi_squared_stat(plain)
        if score < best_score:
            best_score, best_plain, best_key = score, plain, keyword
    sp = SpellChecker()
    corrected_words = [sp.correction(w) or w for w in best_plain.split()]
    corrected_plain = " ".join(corrected_words)
    return corrected_plain, best_key
