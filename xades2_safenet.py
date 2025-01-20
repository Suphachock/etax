from lxml import etree
from PyKCS11 import *
from cryptography import x509
import base64
import datetime
import uuid

def create_rd_etax_xades_etoken(xml_path):
    pkcs11 = PyKCS11Lib()
    pkcs11.load(r"C:\Windows\System32\eToken.dll")
    slots = pkcs11.getSlotList()
    session = pkcs11.openSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login("srsk#10Hilo")

    # Get certificate
    cert_objs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE),
                                   (CKA_CERTIFICATE_TYPE, CKC_X_509)])
    cert_der = bytes(session.getAttributeValue(cert_objs[0], [CKA_VALUE])[0])
    cert = x509.load_der_x509_certificate(cert_der)

    # Get private key
    priv_key = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),
                                  (CKA_KEY_TYPE, CKK_RSA)])[0]

    tree = etree.parse(xml_path)
    root = tree.getroot()
    
    nsmap = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xades': 'http://uri.etsi.org/01903/v1.3.2#',
        'xades141': 'http://uri.etsi.org/01903/v1.4.1#'
    }

    signature_id = f"xmldsig-{str(uuid.uuid4())}"
    signature = etree.SubElement(root, f"{{{nsmap['ds']}}}Signature", 
                               Id=signature_id, nsmap=nsmap)

    signed_info = etree.SubElement(signature, f"{{{nsmap['ds']}}}SignedInfo")
    
    etree.SubElement(signed_info, f"{{{nsmap['ds']}}}CanonicalizationMethod",
                    Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    
    etree.SubElement(signed_info, f"{{{nsmap['ds']}}}SignatureMethod",
                    Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")

    reference = etree.SubElement(signed_info, f"{{{nsmap['ds']}}}Reference",
                               Id=f"{signature_id}-ref0", URI="")
    
    transforms = etree.SubElement(reference, f"{{{nsmap['ds']}}}Transforms")
    etree.SubElement(transforms, f"{{{nsmap['ds']}}}Transform",
                    Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    
    etree.SubElement(reference, f"{{{nsmap['ds']}}}DigestMethod",
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")
    
    canonicalized_doc = etree.tostring(root, method='c14n', 
                                     exclusive=True, with_comments=False)
    
    mechanism = Mechanism(CKM_SHA512)
    digest = session.digest(mechanism, canonicalized_doc)
    doc_digest_value = base64.b64encode(bytes(digest)).decode()
    
    digest_value_elem = etree.SubElement(reference, f"{{{nsmap['ds']}}}DigestValue")
    digest_value_elem.text = doc_digest_value

    signed_props_id = f"{signature_id}-signedprops"
    reference_props = etree.SubElement(
        signed_info,
        f"{{{nsmap['ds']}}}Reference",
        Type="http://uri.etsi.org/01903#SignedProperties",
        URI=f"#{signed_props_id}"
    )
    
    etree.SubElement(reference_props, f"{{{nsmap['ds']}}}DigestMethod",
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")

    canonicalized_signed_info = etree.tostring(signed_info, method='c14n',
                                             exclusive=True, with_comments=False)
    
    mechanism = Mechanism(CKM_SHA512_RSA_PKCS)
    signature_value = session.sign(priv_key, canonicalized_signed_info, mechanism)
    
    signature_value_elem = etree.SubElement(signature, f"{{{nsmap['ds']}}}SignatureValue",
                                          Id=f"{signature_id}-sigvalue")
    signature_value_elem.text = base64.b64encode(bytes(signature_value)).decode()

    key_info = etree.SubElement(signature, f"{{{nsmap['ds']}}}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{{{nsmap['ds']}}}X509Data")
    x509_cert = etree.SubElement(x509_data, f"{{{nsmap['ds']}}}X509Certificate")
    x509_cert.text = base64.b64encode(cert_der).decode()

    object_elem = etree.SubElement(signature, f"{{{nsmap['ds']}}}Object")
    qualifying_props = etree.SubElement(object_elem,
                                      f"{{{nsmap['xades']}}}QualifyingProperties",
                                      Target=f"#{signature_id}")
    
    signed_props = etree.SubElement(qualifying_props,
                                  f"{{{nsmap['xades']}}}SignedProperties",
                                  Id=signed_props_id)
    
    signed_sig_props = etree.SubElement(signed_props,
                                      f"{{{nsmap['xades']}}}SignedSignatureProperties")
    
    signing_time = etree.SubElement(signed_sig_props,
                                  f"{{{nsmap['xades']}}}SigningTime")
    signing_time.text = datetime.datetime.now().astimezone().isoformat()
    
    signing_cert = etree.SubElement(signed_sig_props,
                                  f"{{{nsmap['xades']}}}SigningCertificate")
    
    cert_elem = etree.SubElement(signing_cert, f"{{{nsmap['xades']}}}Cert")
    cert_digest = etree.SubElement(cert_elem, f"{{{nsmap['xades']}}}CertDigest")
    
    etree.SubElement(cert_digest, f"{{{nsmap['ds']}}}DigestMethod",
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")
    
    mechanism = Mechanism(CKM_SHA512)
    cert_digest_value = session.digest(mechanism, cert_der)
    
    digest_value_elem = etree.SubElement(cert_digest, f"{{{nsmap['ds']}}}DigestValue")
    digest_value_elem.text = base64.b64encode(bytes(cert_digest_value)).decode()
    
    issuer_serial = etree.SubElement(cert_elem, f"{{{nsmap['xades']}}}IssuerSerial")
    issuer_name = etree.SubElement(issuer_serial, f"{{{nsmap['ds']}}}X509IssuerName")
    issuer_name.text = str(cert.issuer)
    serial_number = etree.SubElement(issuer_serial, f"{{{nsmap['ds']}}}X509SerialNumber")
    serial_number.text = str(cert.serial_number)

    canonicalized_props = etree.tostring(signed_props, method='c14n',
                                       exclusive=True, with_comments=False)
    
    props_digest_value = session.digest(mechanism, canonicalized_props)
    
    props_digest_value_elem = etree.SubElement(reference_props,
                                             f"{{{nsmap['ds']}}}DigestValue")
    props_digest_value_elem.text = base64.b64encode(bytes(props_digest_value)).decode()

    session.logout()
    session.closeSession()
    return etree.tostring(root, pretty_print=True, encoding='UTF-8')

if __name__ == "__main__":
    xml_path = "invoice.xml"
    signed_xml = create_rd_etax_xades_etoken(xml_path)
    with open('signed_invoice.xml', 'wb') as f:
        f.write(signed_xml)