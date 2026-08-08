import urllib.parse
import base64
import hashlib
import re
from cryptography import x509
from cryptography.x509.oid import NameOID

def _extract_cert_pem_from_xfcc(xfcc: str) -> str:
    """
    XFCC thực tế:

    Hash=...;
    Cert="-----BEGIN%20CERTIFICATE-----%0A..."
    Subject="..."

    """

    match = re.search(r'Cert="([^"]+)"', xfcc)

    if not match:
        raise ValueError(
            'Cert field not found or missing double quotes (") in XFCC header'
        )

    return urllib.parse.unquote(match.group(1))


def _pem_to_der(pem_str: str) -> bytes:

    pem_body = (
        pem_str
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
    )

    pem_body = re.sub(
        r'[^A-Za-z0-9+/=]',
        '',
        pem_body
    )

    padding = len(pem_body) % 4

    if padding:
        pem_body += '=' * (4 - padding)

    return base64.b64decode(pem_body)


def extract_thumbprint_from_xfcc(xfcc: str) -> str:

    pem = _extract_cert_pem_from_xfcc(xfcc)

    der = _pem_to_der(pem)

    digest = hashlib.sha256(der).digest()

    return (
        base64.urlsafe_b64encode(digest)
        .rstrip(b'=')
        .decode()
    )


def extract_cn_from_xfcc(xfcc: str) -> str:

    pem = _extract_cert_pem_from_xfcc(xfcc)

    der = _pem_to_der(pem)

    cert = x509.load_der_x509_certificate(der)

    cn = cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )

    if not cn:
        raise ValueError(
            "Common Name (CN) not found in certificate"
        )

    return cn[0].value