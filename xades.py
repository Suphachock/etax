from lxml import etree
import base64
from datetime import datetime
import pytz
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate


def create_xades_signature(xml_file, cert_file, key_file):
    # สร้าง XML parser ที่รองรับ UTF-8
    parser = etree.XMLParser(encoding='utf-8')
    doc = etree.parse(xml_file, parser)
    root = doc.getroot()

    # โหลด certificate และแปลงเป็น base64
    with open(cert_file, "rb") as f:
        cert_data = f.read()
        cert = load_pem_x509_certificate(cert_data)
        cert_b64 = base64.b64encode(cert_data).decode()

    # โหลด private key
    with open(key_file, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    # สร้าง ID สำหรับ signature จาก serial number ของ certificate
    sig_id = f"xmldsig-{cert.serial_number}"

    # กำหนด namespace สำหรับ XML signature
    NSMAP = {
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'xades': 'http://uri.etsi.org/01903/v1.3.2#',
        'xades141': 'http://uri.etsi.org/01903/v1.4.1#'
    }

    # สร้าง element Signature
    signature = etree.SubElement(
        root, "{http://www.w3.org/2000/09/xmldsig#}Signature", Id=sig_id, nsmap=NSMAP)

    # สร้าง SignedInfo - ข้อมูลที่จะเซ็น
    signed_info = etree.SubElement(
        signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
    # กำหนดวิธีการ canonicalize XML
    etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod",
                     Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    # กำหนดอัลกอริทึมการเซ็น (RSA-SHA512)
    etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod",
                     Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")

    # สร้าง Reference สำหรับเอกสาร
    ref = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference",
                           Id=f"{sig_id}-ref0", URI="")
    # กำหนด Transform สำหรับ enveloped signature
    transforms = etree.SubElement(
        ref, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
    etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform",
                     Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    # กำหนดวิธีการคำนวณ digest (SHA512)
    etree.SubElement(ref, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                     Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")

    # สร้าง Reference สำหรับ SignedProperties
    ref_props = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference",
                                 Type="http://uri.etsi.org/01903#SignedProperties",
                                 URI=f"#{sig_id}-signedprops")
    etree.SubElement(ref_props, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                     Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")

    # สร้าง element เก็บค่า signature
    sig_val = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue",
                               Id=f"{sig_id}-sigvalue")

    # สร้าง KeyInfo สำหรับเก็บข้อมูล certificate
    key_info = etree.SubElement(
        signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
    x509_data = etree.SubElement(
        key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
    x509_cert = etree.SubElement(
        x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
    x509_cert.text = cert_b64

    # สร้าง QualifyingProperties สำหรับ XAdES
    ds_object = etree.SubElement(
        signature, "{http://www.w3.org/2000/09/xmldsig#}Object")
    qualifying_props = etree.SubElement(ds_object, "{http://uri.etsi.org/01903/v1.3.2#}QualifyingProperties",
                                        Target=f"#{sig_id}")

    # สร้าง SignedProperties
    signed_props = etree.SubElement(qualifying_props, "{http://uri.etsi.org/01903/v1.3.2#}SignedProperties",
                                    Id=f"{sig_id}-signedprops")
    signed_sig_props = etree.SubElement(
        signed_props, "{http://uri.etsi.org/01903/v1.3.2#}SignedSignatureProperties")

    # เพิ่มเวลาที่เซ็น
    signing_time = etree.SubElement(
        signed_sig_props, "{http://uri.etsi.org/01903/v1.3.2#}SigningTime")
    signing_time.text = datetime.now(pytz.timezone(
        'Asia/Bangkok')).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"+07:00"

    # เพิ่มข้อมูล certificate ที่ใช้เซ็น
    signing_cert = etree.SubElement(
        signed_sig_props, "{http://uri.etsi.org/01903/v1.3.2#}SigningCertificate")
    cert_ref = etree.SubElement(
        signing_cert, "{http://uri.etsi.org/01903/v1.3.2#}Cert")

    # คำนวณ digest ของ certificate
    cert_digest = etree.SubElement(
        cert_ref, "{http://uri.etsi.org/01903/v1.3.2#}CertDigest")
    etree.SubElement(cert_digest, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                     Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")
    cert_digest_value = etree.SubElement(
        cert_digest, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")

    # เพิ่มข้อมูลผู้ออก certificate
    issuer_serial = etree.SubElement(
        cert_ref, "{http://uri.etsi.org/01903/v1.3.2#}IssuerSerial")
    issuer_name = etree.SubElement(
        issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerName")
    issuer_name.text = cert.issuer.rfc4514_string()
    serial_number = etree.SubElement(
        issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber")
    serial_number.text = str(cert.serial_number)

    # คำนวณค่า digest ต่างๆ
    # Canonicalize SignedProperties
    signed_props_xml = etree.tostring(signed_props, method='c14n')
    doc_xml = etree.tostring(root, method='c14n')  # Canonicalize เอกสารทั้งหมด

    signed_props_hash = hashlib.sha512(
        signed_props_xml).digest()  # Hash ของ SignedProperties
    doc_hash = hashlib.sha512(doc_xml).digest()  # Hash ของเอกสาร
    cert_hash = hashlib.sha512(cert_data).digest()  # Hash ของ certificate

    # เพิ่มค่า digest ลงใน XML
    etree.SubElement(
        ref_props, "{http://www.w3.org/2000/09/xmldsig#}DigestValue").text = base64.b64encode(signed_props_hash).decode()
    etree.SubElement(
        ref, "{http://www.w3.org/2000/09/xmldsig#}DigestValue").text = base64.b64encode(doc_hash).decode()
    cert_digest_value.text = base64.b64encode(cert_hash).decode()

    # ลงนามดิจิทัล
    signed_info_c14n = etree.tostring(
        signed_info, method='c14n')  # Canonicalize SignedInfo
    signature_value = key.sign(  # เซ็นด้วย private key
        signed_info_c14n,
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    sig_val.text = base64.b64encode(
        signature_value).decode()  # แปลงลายเซ็นเป็น base64

    return root


# ใช้งานฟังก์ชัน
signed_root = create_xades_signature(
    "template.xml", "certificate.pem", "private.pem")
# บันทึกไฟล์ XML ที่เซ็นแล้ว
with open("signed.xml", "wb") as f:
    f.write(etree.tostring(signed_root, encoding='utf-8'))
