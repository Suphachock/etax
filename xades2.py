from lxml import etree
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import datetime
import uuid

def create_rd_etax_xades(xml_path, cert_path, key_path):
    tree = etree.parse(xml_path)
    root = tree.getroot()
    
    nsmap = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xades': 'http://uri.etsi.org/01903/v1.3.2#',
        'xades141': 'http://uri.etsi.org/01903/v1.4.1#'
    }
    
    with open(cert_path, 'rb') as cert_file:
        cert = load_pem_x509_certificate(cert_file.read())
    
    with open(key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    signature_id = f"xmldsig-{str(uuid.uuid4())}"
    signature = etree.SubElement(
        root,
        f"{{{nsmap['ds']}}}Signature",
        Id=signature_id,
        nsmap=nsmap
    )

    signed_info = etree.SubElement(signature, f"{{{nsmap['ds']}}}SignedInfo")
    
    etree.SubElement(
        signed_info,
        f"{{{nsmap['ds']}}}CanonicalizationMethod",
        Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    )
    
    etree.SubElement(
        signed_info,
        f"{{{nsmap['ds']}}}SignatureMethod",
        Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
    )

    reference = etree.SubElement(
        signed_info,
        f"{{{nsmap['ds']}}}Reference",
        Id=f"{signature_id}-ref0",
        URI=""
    )
    
    transforms = etree.SubElement(reference, f"{{{nsmap['ds']}}}Transforms")
    etree.SubElement(
        transforms,
        f"{{{nsmap['ds']}}}Transform",
        Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    )
    
    etree.SubElement(
        reference,
        f"{{{nsmap['ds']}}}DigestMethod",
        Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"
    )
    
    canonicalized_doc = etree.tostring(
        root,
        method='c14n',
        exclusive=True,
        with_comments=False
    )
    
    digest = hashes.Hash(hashes.SHA512())
    digest.update(canonicalized_doc)
    doc_digest_value = base64.b64encode(digest.finalize()).decode()
    
    digest_value_elem = etree.SubElement(reference, f"{{{nsmap['ds']}}}DigestValue")
    digest_value_elem.text = doc_digest_value

    signed_props_id = f"{signature_id}-signedprops"
    reference_props = etree.SubElement(
        signed_info,
        f"{{{nsmap['ds']}}}Reference",
        Type="http://uri.etsi.org/01903#SignedProperties",
        URI=f"#{signed_props_id}"
    )
    
    etree.SubElement(
        reference_props,
        f"{{{nsmap['ds']}}}DigestMethod",
        Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"
    )

    canonicalized_signed_info = etree.tostring(
        signed_info,
        method='c14n',
        exclusive=True,
        with_comments=False
    )
    
    signature_value = private_key.sign(
        canonicalized_signed_info,
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    
    signature_value_elem = etree.SubElement(
        signature,
        f"{{{nsmap['ds']}}}SignatureValue",
        Id=f"{signature_id}-sigvalue"
    )
    signature_value_elem.text = base64.b64encode(signature_value).decode()

    key_info = etree.SubElement(signature, f"{{{nsmap['ds']}}}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{{{nsmap['ds']}}}X509Data")
    x509_cert = etree.SubElement(x509_data, f"{{{nsmap['ds']}}}X509Certificate")
    x509_cert.text = base64.b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode()

    object_elem = etree.SubElement(signature, f"{{{nsmap['ds']}}}Object")
    qualifying_props = etree.SubElement(
        object_elem,
        f"{{{nsmap['xades']}}}QualifyingProperties",
        Target=f"#{signature_id}"
    )
    
    signed_props = etree.SubElement(
        qualifying_props,
        f"{{{nsmap['xades']}}}SignedProperties",
        Id=signed_props_id
    )
    
    signed_sig_props = etree.SubElement(
        signed_props,
        f"{{{nsmap['xades']}}}SignedSignatureProperties"
    )
    
    signing_time = etree.SubElement(
        signed_sig_props,
        f"{{{nsmap['xades']}}}SigningTime"
    )
    signing_time.text = datetime.datetime.now().astimezone().isoformat()
    
    signing_cert = etree.SubElement(
        signed_sig_props,
        f"{{{nsmap['xades']}}}SigningCertificate"
    )
    
    cert_elem = etree.SubElement(signing_cert, f"{{{nsmap['xades']}}}Cert")
    cert_digest = etree.SubElement(cert_elem, f"{{{nsmap['xades']}}}CertDigest")
    
    etree.SubElement(
        cert_digest,
        f"{{{nsmap['ds']}}}DigestMethod",
        Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"
    )
    
    cert_digest_obj = hashes.Hash(hashes.SHA512())
    cert_digest_obj.update(cert.public_bytes(serialization.Encoding.DER))
    cert_digest_value = base64.b64encode(cert_digest_obj.finalize()).decode()
    
    digest_value_elem = etree.SubElement(cert_digest, f"{{{nsmap['ds']}}}DigestValue")
    digest_value_elem.text = cert_digest_value
    
    issuer_serial = etree.SubElement(cert_elem, f"{{{nsmap['xades']}}}IssuerSerial")
    issuer_name = etree.SubElement(issuer_serial, f"{{{nsmap['ds']}}}X509IssuerName")
    issuer_name.text = str(cert.issuer)
    serial_number = etree.SubElement(issuer_serial, f"{{{nsmap['ds']}}}X509SerialNumber")
    serial_number.text = str(cert.serial_number)

    canonicalized_props = etree.tostring(
        signed_props,
        method='c14n',
        exclusive=True,
        with_comments=False
    )
    
    props_digest = hashes.Hash(hashes.SHA512())
    props_digest.update(canonicalized_props)
    props_digest_value = base64.b64encode(props_digest.finalize()).decode()
    
    props_digest_value_elem = etree.SubElement(reference_props, f"{{{nsmap['ds']}}}DigestValue")
    props_digest_value_elem.text = props_digest_value

    return etree.tostring(root, pretty_print=True, encoding='UTF-8')

if __name__ == "__main__":
    xml_path = "template.xml"
    cert_path = "certificate.pem"
    key_path = "private.pem"
    
    signed_xml = create_rd_etax_xades(xml_path, cert_path, key_path)
    with open('signed_invoice999.xml', 'wb') as f:
        f.write(signed_xml)