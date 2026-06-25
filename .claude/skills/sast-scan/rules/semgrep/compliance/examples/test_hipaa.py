# HIPAA compliance rule test fixtures

# --- hipaa.encryption-weak-algorithm ---

def hash_phi_unsafe(patient_data: str):
    import hashlib
    # ruleid: hipaa.encryption-weak-algorithm
    digest = hashlib.md5(patient_data.encode())
    return digest

def hash_phi_unsafe_sha1(patient_data: str):
    import hashlib
    # ruleid: hipaa.encryption-weak-algorithm
    digest = hashlib.sha1(patient_data.encode())
    return digest

def hash_phi_safe(patient_data: str):
    import hashlib
    # ok: hipaa.encryption-weak-algorithm
    digest = hashlib.sha256(patient_data.encode())
    return digest

# --- hipaa.session-no-timeout ---

# ok: hipaa.session-no-timeout
SESSION_COOKIE_AGE = 3600
