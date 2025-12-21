class BaseAuthority:
    def __init__(self, crypto_core, authority_id, attributes):
        self.crypto_core = crypto_core
        self.authority_id = authority_id
        self.attributes = attributes
        
        # 1. Generate Keys immediately upon initialization
        print(f"🔑 Initializing Authority: {self.authority_id}")
        self.public_key, self.secret_key = self.crypto_core.setup_authority(self.authority_id)
        
        # 2. Safety Check
        if self.secret_key is None:
            raise ValueError(f"CRITICAL: Failed to generate secret key for {self.authority_id}")

    def issue_key(self, user_gid, attribute):
        # Delegate to crypto core
        full_attr = f"{self.authority_id}_{attribute}"
        return self.crypto_core.generate_user_key(self.secret_key, user_gid, full_attr)