from lxml import etree
import base64
from datetime import datetime
import pytz
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate, NameOID
from cryptography.hazmat.primitives import serialization

def get_signer_info(xml_file):
   tree = etree.parse(xml_file)
   root = tree.getroot()
   
   ns = {'ds': 'http://www.w3.org/2000/09/xmldsig#'}
   cert_b64 = root.find('.//ds:X509Certificate', namespaces=ns).text
   cert_der = base64.b64decode(cert_b64)
   cert_pem = b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(cert_der) + b'\n-----END CERTIFICATE-----'
   cert = load_pem_x509_certificate(cert_pem)

   subject = cert.subject
   for attribute in subject:
       if attribute.oid == NameOID.COMMON_NAME:
           print(f"ผู้ลงนาม: {attribute.value}")
           break

get_signer_info("./signed-ETDA-invoice.xml")