#!/usr/bin/env python
from flask import Flask, request, redirect, url_for, make_response, session
from markupsafe import escape
from saml2 import entity
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from conf.sp_conf import CONFIG, BASE_URL
from xml.etree import ElementTree
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from pprint import pprint
from saml2.saml import NAMEID_FORMAT_PERSISTENT, NameID
from saml2.metadata import entity_descriptor
import os
import base64
import argparse

# Define the argument parser and parse arguments
parser = argparse.ArgumentParser(description='Test SAML2 service provider with SLO capability')
parser.add_argument('--debug', action='store_true', help='Enable debug mode')
args = parser.parse_args()

# Function to handle logging
def debug_log(message):
    """
    Pprint log and error messages if the --debug argument
    is present on the command line.

    Args:
        message (str): informative message

    Returns:
        None
    """
    if args.debug:
        pprint(message)


def saml_client_for(config):
    """
    Create a SAML client using the provided configuration.

    Args:
        config (str): Path to the SAML configuration file.

    Returns:
        Saml2Client: A SAML client instance.

    """
    conf = Saml2Config()
    conf.load(config)
    return Saml2Client(conf)

app = Flask(__name__)
# Set the secret key to some random bytes. Keep this really secret!
# This enables Flask session cookies
app.secret_key = '^ovdD@8Sj3P!8&k$8dYze$kweWMVu88jbzV^o3r5LUs7cPU2'

@app.route("/")
def hello():
    """
    Displays a welcome message and user information if the user is authenticated,
    otherwise displays a login link.

    Returns:
        tuple: A tuple containing the HTML content and the HTTP status code.
    """
    # Check if user is authenticated
    if session.get('is_authenticated'):
        name_id = escape(session.get('name_id', ''))
        given_name = escape(session.get('given_name', ''))
        surname = escape(session.get('surname', ''))

        # User is authenticated, display user info and logout link
        html = f"<h1>Welcome, {session['given_name']} {session['surname']}!</h1>"
        html += f"<p>Your ID: {session['name_id']}</p>"
        html += "<p><a href='/logout'>Logout</a></p>"
    else:
        # User is not authenticated, display login link
        html = "<h1>Welcome to the CUNY Performance Test Service Provider</h1>"
        html += "<p>SP entityID: <a href=" + BASE_URL + "/saml/metadata>" + BASE_URL + "/saml/metadata</a></p>"
        html += "<p>You are not logged in.</p>"
        html += "<p><a href='/login'>Login via SAML</a></p>"

    html += "<p>(c) 2020-2023 Florian Lengyel CUNY and ChatGPT4.</p>"
    return html, 200


@app.route('/login')
def login():
    """
    Initiates the SAML authentication process by creating an authentication request and redirecting the user to the IdP's login page.

    Returns:
        If the redirect URL is available, the function redirects the user to the IdP's login page.
        If the redirect URL is not available, the function returns an error message with status code 500.
    """
    client = saml_client_for(CONFIG)

    # Create the SAML authentication request
    (session_id, result) = client.prepare_for_authenticate()

    # Redirect the user to the IdP's login page
    redirect_url = None
    for key, value in result['headers']:
        if key == 'Location':
            redirect_url = value
            break

    if redirect_url:
        return redirect(redirect_url)
    else:
        return "Error: Couldn't redirect to IdP for login.", 500


@app.route('/saml/acs/', methods=['POST'])
def acs():
    """
    Process the SAML Assertion Consumer Service (ACS) request.

    This function handles the SAML response received from the Identity Provider (IdP) after the user
    has been authenticated. It extracts the user's attributes from the SAML response, sets the user
    session, and redirects the user to the 'hello' endpoint.

    Returns:
        A redirect response to the 'hello' endpoint if the SAML response is successfully processed.
        An error message with status code 500 if there is an exception during processing.
    """
    client = saml_client_for(CONFIG)
    try:
        # Parse the SAML Response
        saml_response = request.form.get('SAMLResponse')
        authn_response = client.parse_authn_request_response(saml_response, entity.BINDING_HTTP_POST)

        # Extract the user's NameID and attributes
        name_id = authn_response.assertion.subject.name_id.text
        debug_log(f"name_id: {name_id}")

        # Accessing attributes directly from the assertion
        attributes = {}
        for statement in authn_response.assertion.attribute_statement:
            for attribute in statement.attribute:
                # Assuming single value attributes for simplicity
                attributes[attribute.name] = attribute.attribute_value[0].text

        # Example of extracting specific attributes
        given_name = attributes.get('givenName', None)
        surname = attributes.get('sn', None)

        # Set the user session
        session['name_id'] = name_id
        session['given_name'] = given_name
        session['surname'] = surname
        session['is_authenticated'] = True

        #print(authn_response.assertion)

        # Ensure the assertion object is a string
        assertion_string = str(authn_response.assertion)

        # Encode the string to bytes
        assertion_bytes = assertion_string.encode('utf-8')

        # Parse the XML string
        root = ElementTree.fromstring(assertion_bytes)

        # Find the AuthnStatement element
        authn_statement = root.find('.//saml:AuthnStatement', namespaces={'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'})

        # Get the session index
        session_index = authn_statement.attrib.get('SessionIndex')

        # Print the session index
        debug_log(f"Session index: {session_index}")

        session['session_index'] = session_index

        return redirect(url_for('hello'))

    except Exception as e:
        # Log the exception for debugging
        debug_log(f"SAML ACS Error: {e}")

        # Clear any existing session and display error
        session.clear()
        return "INTERNAL SERVER ERROR", 500

    # Load and parse the metadata XML file

@app.route('/logout')
def logout():
    """
    Constructs a logout request for the SAML service provider.

    Returns:
        str: The HTML form containing the encoded logout request.
    """
    client = saml_client_for(CONFIG)

    # Ensure the user is logged in before proceeding
    if not session.get('is_authenticated'):
        return redirect(url_for('hello'))

    # Construct the full path to the metadata file
    metadata_file_path = os.path.join(os.path.dirname(__file__), CONFIG['metadata']['local'][0])
    idp_metadata_file_path = os.path.abspath(metadata_file_path)
    tree = ElementTree.parse(idp_metadata_file_path)
    root = tree.getroot()

    # Define the XML namespaces used in the metadata file
    namespaces = {
        'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
    }

    # Find the SingleLogoutService element for HTTP POST binding and extract the URL
    sls_element = root.find(".//md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']", namespaces)
    idp_logout_endpoint = sls_element.get('Location') if sls_element is not None else None


    if not idp_logout_endpoint:
        debug_log("Could not find a Single Logout Service endpoint with POST binding in the IdP metadata.")
        return "Error: No SLS endpoint found for IdP", 500
    else:
        debug_log(f"idp_logout_endpoint: {idp_logout_endpoint}")


    # Create a NameID object with the user's name_id value in Persistent format
    user_name_id = NameID(format=NAMEID_FORMAT_PERSISTENT, text=session.get('name_id'))
    sp_entity_id = CONFIG['entityid']

    # Create the LogoutRequest
    try:
        # The create_logout_request method returns a tuple: (request_id, logout_request_xml)
        _, logout_request_xml = client.create_logout_request(
            name_id=user_name_id,
            destination=idp_logout_endpoint,  # Use the actual IdP's logout endpoint
            issuer_entity_id=sp_entity_id
        )
        debug_log(f"Logout request XML: {logout_request_xml}")
    except Exception as e:
        debug_log(f"Error creating logout request: {e}")
        return "Error creating logout request", 500

    # Encode the LogoutRequest (typically base64)
    #print(f"dir(logout_request_xml): {dir(logout_request_xml)}")
    logout_request_xml_str = logout_request_xml.to_string()
    debug_log(logout_request_xml_str)
    encoded_request = base64.b64encode(logout_request_xml_str).decode()

    # Create the HTML form using the encoded logout request
    html_form = f"""
    <html>
        <body onload="document.forms[0].submit()">
            <form method="POST" action="{idp_logout_endpoint}">
                <input type="hidden" name="SAMLRequest" value="{encoded_request}">
                <!-- Add a hidden RelayState field if required -->
            </form>
        </body>
    </html>
    """
    return html_form

@app.route('/saml/sls/', methods=['GET','POST'])
def sls():
    """
    Process the Single Logout Service (SLS) request.

    This function handles the SAML Single Logout (SLO) request.
    It checks if the request contains a SAMLRequest or SAMLResponse parameter.
    If a SAMLRequest is found, it parses the request, terminates the user's session,
    creates a LogoutResponse, and returns a modified HTML response with a JavaScript snippet for redirection.
    If a SAMLResponse is found, it parses the response, extracts specific information from the parsed XML,
    clears the user's session, and redirects to a specified URL.

    If neither SAMLRequest nor SAMLResponse is found, it returns an error message.

    Returns:
        str: The modified HTML response or an error message.
    """
    client = saml_client_for(CONFIG)

    debug_log(f"In /saml/sls/ with request.args {request.args}")

    if 'SAMLRequest' in request.args:
        try:
            # Manually iterate over request.args to find SAMLRequest
            # other methods do not work!
            logout_request_encoded = None
            for key, value in request.args.items():
                if key == 'SAMLRequest':
                    logout_request_encoded = value
                    break

            if logout_request_encoded:
                logout_request = client.parse_logout_request(
                    logout_request_encoded, BINDING_HTTP_REDIRECT)

                # Terminate the user's session
                session.clear()

                xmlstr = logout_request.xmlstr.decode('utf-8')
                debug_log(f"xmlstr.decode('utf-8'): {xmlstr}")
                root = ElementTree.fromstring(xmlstr)
                request_id = root.attrib.get('ID', None)
                debug_log(f"Request ID: {request_id}")

                if request_id:
                    # Construct the logout response
                    response_binding = BINDING_HTTP_POST  # or whichever binding you are using
                    sign_post = True  # or False, depending on your requirement
                    sign_alg = None  # specify if you have a specific signing algorithm
                    digest_alg = None  # specify if you have a specific digest algorithm

                    # Create the LogoutResponse
                    response = client.create_logout_response(
                                   logout_request.message,
                                   bindings=[response_binding],
                                   # status=status,  # Ensure 'status' is defined appropriately
                                   sign=sign_post,
                                   sign_alg=sign_alg,
                                   digest_alg=digest_alg)

                    # Get the response arguments
                    rinfo = client.response_args(logout_request.message, [response_binding])

                    # Apply the binding and get the HTTP response
                    http_response = client.apply_binding(
                                        rinfo["binding"],
                                        response,
                                        rinfo["destination"],
                                        # relay_state,  # Ensure 'relay_state' is defined or received from the request
                                        response=True,
                                        sign=sign_post,
                                        sigalg=sign_alg)


                    # Extract the HTTP response and prepare for modification
                    response_html = http_response['data']

                    # Define the JavaScript snippet for redirection
                    # The indentation below reduces the number of spaces
                    js_redirect = """
    <script>
        setTimeout(function() {{
            window.location.href = '{}';
        }}, 5000); // Redirect after 5 seconds
    </script>
""".format(url_for('hello'))  # Replace with your own URL

                    # Insert the JavaScript snippet into the HTML response
                    response_html = response_html.replace('</body>', js_redirect + '</body>')

                    debug_log(f"http_response before modification: {http_response}")
                    debug_log(f"response_html: {response_html}")

                    return response_html  # Return the modified HTML response

        except Exception as e:
            return f"Error processing SAMLRequest: {e}", 500

    elif 'SAMLResponse' in request.args:
        try:
            # Manually iterate over request.args to find SAMLResponse
            # other methods do not work!
            logout_response_encoded = None
            for key, value in request.args.items():
                if key == 'SAMLResponse':
                    logout_response_encoded = value
                    break

            if logout_response_encoded:
                try:
                    authn_response = client.parse_authn_request_response(logout_response_encoded,
                                                                          entity.BINDING_HTTP_REDIRECT)
                    debug_log(f"authn_response: {authn_response}")

                    # Extract specific information from the parsed XML
                    issuer = authn_response.issuer()
                    status_ok = authn_response.status_ok()

                    debug_log(f"Issuer: {issuer if issuer is not None else 'Not found'}")
                    debug_log(f"Status OK: {status_ok}")

                except ElementTree.ParseError as e:
                    debug_log(f"Error parsing XML: {e}")

            session.clear()
            return redirect(url_for('hello'))

        except Exception as e:
            session.clear()  # I still want to clear the session
            return f"Error processing SAMLResponse: {e}", 500

    else:
        # If neither SAMLRequest nor SAMLResponse is found, return an error or a default response
        return "Invalid SLO request", 400

@app.route('/saml/metadata/')
def metadata():
    """
    Generates the metadata for the SAML service provider.

    Returns:
        flask.Response: The metadata XML response.
    """
    conf = Saml2Config()
    conf.load(CONFIG)
    metadata_content = entity_descriptor(conf).to_string()
    response = make_response(metadata_content, 200)
    response.headers['Content-Type'] = 'application/xml'
    return response

if __name__ == "__main__":
    # replace server.pem with your own server certificate and server.key with your own server key
    app.run(debug=True, host='0.0.0.0', port=8443, ssl_context=('/etc/pki/tls/server.pem', '/etc/pki/tls/private/server.key'))

