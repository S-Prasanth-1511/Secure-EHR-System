from .base_authority import BaseAuthority

class MedicalAuthority(BaseAuthority):
    def __init__(self, crypto_core, config):
        # UPDATED: Look for 'MA' instead of 'MEDICAL_AUTHORITY'
        authority_config = config['MA']
        
        super().__init__(
            crypto_core=crypto_core,
            authority_id=authority_config['id'],
            attributes=authority_config['attributes']
        )
