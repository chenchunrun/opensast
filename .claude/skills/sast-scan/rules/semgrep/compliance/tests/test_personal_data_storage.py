import logging


def store_user(db, id_card, phone, email, encrypted_phone):
    # ruleid: gbt35273.personal-data-plaintext-storage
    db.insert({"id_card": id_card, "name": "alice"})

    # ruleid: gbt35273.personal-data-plaintext-storage
    db.insert({"phone": phone, "name": "bob"})

    # ruleid: gbt35273.personal-data-plaintext-storage
    db.insert({"email": email, "name": "carol"})

    # ok: gbt35273.personal-data-plaintext-storage
    db.insert({"phone_hash": encrypted_phone, "name": "dave"})

    # ruleid: gbt35273.logging-personal-data
    logging.info("user registered", email=email)

    # ok: gbt35273.logging-personal-data
    logging.info("user registered", event="signup")
