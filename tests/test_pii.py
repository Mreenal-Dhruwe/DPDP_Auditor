"""Field-name matching (scanner/pii.py)."""

import pytest

from scanner.pii import default_matcher, split_words


def test_split_words():
    assert split_words("customerPhoneNo") == ["customer", "phone", "no"]
    assert split_words("date-of-birth") == ["date", "of", "birth"]
    assert split_words("HTTPRequestBody") == ["http", "request", "body"]


@pytest.mark.parametrize(("name", "label", "sensitivity", "confidence", "protected"), [
    ("email", "email", "medium", "high", False),
    ("aadhaar", "aadhaar", "high", "high", False),
    ("ph_no", "phone", "medium", "high", False),           # synonym
    ("dateOfBirth", "date_of_birth", "medium", "high", False),
    ("customer_phone_no", "phone", "medium", "medium", False),  # part of the name
    ("user_email", "email", "medium", "medium", False),
    ("password_hash", "password", "high", "medium", True),  # protected
    ("aadhaar_encrypted", "aadhaar", "high", "medium", True),
    ("emial", "email", "medium", "low", False),            # typo, fuzzy
    ("adress", "address", "medium", "low", False),
])
def test_personal_data_names(name, label, sensitivity, confidence, protected):
    match = default_matcher().match(name)
    assert (match.label, match.sensitivity, match.confidence, match.protected) == (
        label, sensitivity, confidence, protected)


@pytest.mark.parametrize("name", [
    "user_id", "id", "row", "city", "job", "span", "allocation", "company",  # not personal data
    "email_template", "phone_verified", "health_check", "file_location",    # about the field
    "none", "done", "notice_version", "created_at", "purpose",
])
def test_not_personal_data(name):
    assert default_matcher().match(name) is None
