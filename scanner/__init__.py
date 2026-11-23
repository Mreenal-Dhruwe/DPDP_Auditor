"""DPDP Compliance Auditor - the scanning engine.

Reads a project's source code and configuration (it never imports or runs them), finds
where personal data is mishandled, and maps each finding to the DPDP Act, 2023 and the
DPDP Rules, 2025 using rules/dpdp_rules.yml. Legal mapping is indicative, not legal advice.
"""

__version__ = "0.1.0"
