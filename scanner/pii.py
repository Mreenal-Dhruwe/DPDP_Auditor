"""PII finder: does a name (variable, attribute, column, form field, dict key) refer to
personal data?

    from scanner.pii import default_matcher
    default_matcher().match("customerPhoneNo")   # PiiMatch(label='phone', sensitivity='medium', ...)

How a name is matched (vocabulary: personal_data.field_names in rules/dpdp_rules.yml):
1. split camelCase / snake_case / kebab-case into words: customerPhoneNo -> customer, phone, no
2. the whole name, exactly or via a synonym (ph_no, mob, contact_no ...)   -> confidence high
3. a run of words inside it (customer_phone_no -> phone_no -> phone)         -> confidence medium
   - not when another word shows it is about the field, not the data:
     email_template, phone_verified, health_check, file_location
   - marked `protected` when another word shows the value is hashed, encrypted
     or tokenised: password_hash, aadhaar_encrypted, pan_token
4. fuzzy, for typos (emial, adress): difflib ratio >= 0.8, same first letter,
   at most one edit for words of 5 letters or fewer, never for words of 3 or fewer
   (so dob != job, pan != span), never for common words              -> confidence low

Still to come (hours 4-14): value regexes (Aadhaar with Verhoeff, PAN ...) and form input
types (type="tel") for the PII inventory.
"""

import difflib
import re
from dataclasses import dataclass
from functools import lru_cache

# Synonym (normalised, words joined with "_") -> label from the YAML field lists.
SYNONYMS = {
    "ph_no": "phone", "phone_no": "phone", "phone_number": "phone", "contact_no": "phone",
    "contact_number": "phone", "msisdn": "phone", "mob": "mobile", "mob_no": "mobile",
    "mobile_no": "mobile", "mobile_number": "mobile", "cell": "mobile",
    "e_mail": "email", "email_id": "email", "email_address": "email", "mail_id": "email",
    "aadhaar_no": "aadhaar", "aadhaar_number": "aadhaar", "aadhar_no": "aadhaar", "uidai": "aadhaar",
    "pan_no": "pan", "pan_number": "pan", "pan_card": "pan",
    "birth_date": "dob", "birthdate": "dob", "birthday": "dob",
    "addr": "address", "street": "address", "address_line": "address",
    "pin_code": "pincode", "postal_code": "pincode", "zip": "pincode", "zipcode": "pincode", "zip_code": "pincode",
    "latitude": "lat", "longitude": "lng", "lon": "lng",
    "acc_no": "account_number", "account_no": "account_number", "acct_no": "account_number",
    "bank_account_number": "account_number", "card_no": "card_number", "credit_card": "card_number",
    "ip": "ip_address", "vpa": "upi", "upi_id": "upi", "passport_no": "passport",
    "pwd": "password", "passwd": "password",
    "first_name": "full_name", "last_name": "full_name", "fullname": "full_name", "customer_name": "full_name",
}
# Another word like these means the name is about the field, not the personal data.
NOT_DATA_WORDS = {
    "template", "type", "types", "field", "label", "format", "count", "length", "regex", "pattern",
    "column", "url", "uri", "path", "file", "dir", "verified", "verify", "enabled", "flag", "sent",
    "status", "domain", "check", "config", "setting", "settings", "validator", "valid", "required",
    "max", "min", "placeholder", "input", "button", "error", "subject", "provider", "service",
    "mode", "policy", "reset", "otp", "changed", "updated", "visible", "opt",
}
# Another word like these means the value is protected (hashed, encrypted, tokenised, masked).
PROTECTED_WORDS = {
    "hash", "hashed", "digest", "encrypted", "enc", "cipher", "ciphertext", "token", "tokenized",
    "tokenised", "masked", "salt", "salted", "last4",
}
COMMON_WORDS = {"none", "done", "one", "name", "data", "date", "time", "user", "info", "value", "phase"}


@dataclass(frozen=True)
class PiiMatch:
    label: str  # e.g. "phone", "aadhaar"
    sensitivity: str  # "high" | "medium" (from the YAML lists)
    confidence: str  # "high" (whole name) | "medium" (part of the name) | "low" (fuzzy)
    protected: bool = False  # hashed / encrypted / tokenised


def split_words(name: str) -> list[str]:
    """'customerPhoneNo' -> ['customer', 'phone', 'no']; 'date-of-birth' -> ['date', 'of', 'birth']."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return re.findall(r"[a-z]+|\d+", spaced.lower())


def _one_edit_apart(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        swapped = len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
        return len(diffs) <= 1 or swapped  # one substitution, or two neighbours swapped (emial)
    short, long_ = sorted((a, b), key=len)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


class PiiMatcher:
    def __init__(self, high: list[str], medium: list[str]):
        self.sensitivity = {"_".join(split_words(n)): "medium" for n in medium}
        self.sensitivity.update({"_".join(split_words(n)): "high" for n in high})
        self.fuzzy_words = sorted(w for w in self.sensitivity if "_" not in w and len(w) >= 4)

    def _label(self, key: str) -> str | None:
        label = SYNONYMS.get(key, key)
        return label if label in self.sensitivity else None

    def match(self, name: str) -> PiiMatch | None:
        words = split_words(name)
        if not words or all(w.isdigit() for w in words):
            return None
        label = self._label("_".join(words))
        if label:
            return PiiMatch(label, self.sensitivity[label], "high")
        found = self._match_part(words)
        if found:
            return found
        return self._match_fuzzy(words)

    def _match_part(self, words: list[str]) -> PiiMatch | None:
        for size in range(len(words) - 1, 0, -1):  # longest run of words first
            for i in range(len(words) - size + 1):
                label = self._label("_".join(words[i:i + size]))
                if not label:
                    continue
                others = set(words[:i] + words[i + size:])
                if others & NOT_DATA_WORDS:
                    return None
                return PiiMatch(label, self.sensitivity[label], "medium", protected=bool(others & PROTECTED_WORDS))
        return None

    def _match_fuzzy(self, words: list[str]) -> PiiMatch | None:
        if set(words) & NOT_DATA_WORDS:
            return None
        for word in words:
            if len(word) < 4 or word in COMMON_WORDS:
                continue
            for candidate in difflib.get_close_matches(word, self.fuzzy_words, n=3, cutoff=0.8):
                if candidate[0] != word[0] or (len(word) <= 5 and not _one_edit_apart(word, candidate)):
                    continue
                others = set(words) - {word}
                return PiiMatch(candidate, self.sensitivity[candidate], "low", protected=bool(others & PROTECTED_WORDS))
        return None


@lru_cache
def default_matcher() -> PiiMatcher:
    """Matcher built from the field lists in the rules file (read once per process)."""
    from scanner.rules_loader import load_rules  # here, not at the top: rules_loader may import pii later

    names = load_rules().personal_data.field_names
    return PiiMatcher(names.high, names.medium)
