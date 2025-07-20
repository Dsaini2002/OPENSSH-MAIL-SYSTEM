# This function takes the same structure as in compose_window.py
def decrypt_encrypted_email(encrypted_data_dict):
    """
    Decrypt the email and return a dictionary similar in structure.
    """
    try:
        from email_crypto import decrypt_and_verify_email
    except ImportError:
        raise Exception("email_crypto module not available!")

    # Prepare input for decryption
    decryption_input = {
        "encrypted_data": encrypted_data_dict["encrypted_data"],
        "signature": encrypted_data_dict["signature"],
        "sig_public_key": encrypted_data_dict["keys"]["sig_public_key"],
        "shared_secret": encrypted_data_dict["keys"]["shared_secret"]
    }

    # Call decrypt function
    decrypted = decrypt_and_verify_email(
        decryption_input,
        encrypted_data_dict["keys"]["kem_private_key"]
    )

    # Return dictionary with the same structure
    return {
        "decrypted_body": decrypted.get("plaintext", ""),
        "verified": decrypted.get("verified", False),
        "error": decrypted.get("error", False),
        "error_message": decrypted.get("error_message", ""),
        "original_encrypted_data": encrypted_data_dict
    }
