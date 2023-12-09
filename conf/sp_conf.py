from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

BASE_URL = "https://example.org"


CONFIG = {
    'entityid': BASE_URL + '/saml/metadata/',
    'service': {
        'sp': {
            'endpoints': {
                'assertion_consumer_service': [
                    (BASE_URL + '/saml/acs/', BINDING_HTTP_POST),
                ],
                'single_logout_service': [
                    (BASE_URL + '/saml/sls/', BINDING_HTTP_REDIRECT),
                    (BASE_URL + '/saml/sls/', BINDING_HTTP_POST)
                ],
            },
            'allow_unsolicited': True,
            'authn_requests_signed': True,
            'logout_requests_signed': True,
            'want_assertions_signed': True,
            'want_response_signed': False,
        },
    },
    'key_file': 'conf/sp_key.pem',
    'cert_file': 'conf/sp_cert.pem',
    # Additional configurations ...
    'metadata': {
        'local': ['conf/idp-metadata.xml'],
    }
}

