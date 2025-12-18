from .base_authority import BaseAuthority

class HospitalAuthority(BaseAuthority):
    def __init__(self, crypto_core, config):
        # UPDATED: Look for 'HA' instead of 'HOSPITAL_AUTHORITY'
        authority_config = config['HA']
        
        super().__init__(
            crypto_core=crypto_core,
            authority_id=authority_config['id'],
            attributes=authority_config['attributes']
        )
