# SAML2 Service Provider with Single Logout Capability

This project implements a Flask-based SAML2 Service Provider (SP) with Single Logout (SLO) capability. It is designed to test and demonstrate the integration of SAML2 authentication and Single Logout functionality using the Python library pysaml2.

## Features

- SAML2 authentication.
- Single Logout (SLO) service.
- Debug mode for detailed logging.
- Integration with Identity Providers (IdP) supporting SAML2.

### Prerequisites

- Python 3.x
- Flask
- pysaml2
- A valid SAML2 Identity Provider (IdP) for testing.

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/flengyel/pysaml2-service-provider.git
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

   *Note: You might need to create and activate a virtual environment before running the above command.*

### Configuration

1. Update `conf/sp_conf.py` with the appropriate SAML2 configuration for your environment.
2. Replace `BASE_URL` in `conf/sp_conf.py` with your service provider's base URL.
3. Install an x509 signing certificate and in `conf/sp_cert.pem` and `conf/sp_key.pem`, respectively.
4. Change `server.pem` and `server.key` at the end of `sp.py` to refer to the server certificate and key for this service provider. 
5. The service provider metadata will be accessible from `BASE_URL/saml/metadata` while the service provider runs.
6. Install your Identity Provider (IdP) metadata in `conf/idp-metadata.xml`
7. Configure your Identity Provider (IdP) to trust this Service Provider using the service provider metadata at `BASE_URL/saml/metadata`.
8. Consider augmenting the service provider metadata with `ResponseLocation` set equal to the `SingleLogout` `Location` value (the same endpoint).

### Running the Application

1. Run the Flask application:

   ```bash
   source bin/activate
   python sp.py
   ```

2. Access the application at `https://BASE_URL:8443` (or your configured URL and port).

### Enabling Debug Mode

Use the `--debug` flag when starting the application to enable detailed logging:

```bash
python sp.py --debug
```

## Usage

1. Navigate to the main page (`/` route).
2. Click 'Login via SAML' to authenticate using the configured IdP.
3. After authentication, user details will be displayed with a logout option.
4. Click 'Logout' to initiate the Single Logout process.

## Contributing

Contributions to this project are welcome. Please ensure to follow the guidelines provided in CONTRIBUTING.md.

## License

This project is licensed under the MIT license. See the LICENSE file for details.

## Acknowledgements

- Florian Lengyel, CUNY
- ChatGPT4
- Contributors to the pysaml2 library
