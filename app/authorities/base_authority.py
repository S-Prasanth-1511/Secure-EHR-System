class BaseAuthority:
    def __init__(self, crypto_core, authority_id, attributes, public_key=None, secret_key=None):
        self.crypto_core = crypto_core
        self.id = authority_id
        self.attributes = attributes
        self.public_key = public_key
        self.secret_key = secret_key

    def setup(self):
        if self.public_key is None or self.secret_key is None:
            print(f"[{self.id}] Generating keys...")
            # attributes removed from call to match library signature
            (pk, sk) = self.crypto_core.setup_authority(self.id)
            self.public_key = pk
            self.secret_key = sk
            print(f"[{self.id}] Key generation complete.")

    def get_public_key(self):
        return self.public_key

    def issue_user_key(self, user_gid, attribute):
        # DIRECT ISSUE: No checking, trust the input.
        print(f"[{self.id}] DIRECT ISSUE: Generating key for '{attribute}' -> '{user_gid}'")
        return self.crypto_core.generate_user_key(self.secret_key, user_gid, attribute)
