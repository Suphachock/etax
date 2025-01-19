# Import libraries ที่จำเป็น
import PyKCS11
from lxml import etree
import base64
from datetime import datetime
import pytz
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

# ฟังก์ชันสำหรับเซ็นด้วย HSM
def sign_with_safenet(data_to_sign):
   # สร้าง PKCS#11 library object
   lib = PyKCS11.PyKCS11Lib()
   # โหลด HSM driver
   lib.load(r'C:\Windows\System32\eTPKCS11.dll')

   # แสดงข้อมูล library
   print("Library Info:", lib.getInfo())

   # ดึงข้อมูล slots ทั้งหมด
   slots = lib.getSlotList()
   for slot in slots:
       # แสดงข้อมูล slot และ token
       print("Slot Info:", lib.getSlotInfo(slot))
       print("Token Info:", lib.getTokenInfo(slot))

   # ใช้ slot แรก
   slot = slots[0]
   # เปิด session
   session = lib.openSession(slot)
   # login ด้วย PIN
   session.login('pin')

   # ค้นหา private key
   private_key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])[0]
   # เซ็นข้อมูลด้วย SHA512-RSA
   signature = session.sign(private_key, data_to_sign, PyKCS11.Mechanism(PyKCS11.CKM_SHA512_RSA_PKCS))

   # logout และปิด session
   session.logout()
   session.closeSession()
   return bytes(signature)

# ฟังก์ชันสร้าง XAdES signature
def create_xades_signature(xml_file, cert_file):
   # สร้าง XML parser ที่รองรับ UTF-8
   parser = etree.XMLParser(encoding='utf-8')
   doc = etree.parse(xml_file, parser)
   root = doc.getroot()

   # โหลดและแปลง certificate เป็น base64
   with open(cert_file, "rb") as f:
       cert_data = f.read()
       cert = load_pem_x509_certificate(cert_data)
       cert_b64 = base64.b64encode(cert_data).decode()

   # สร้าง signature ID จาก serial number ของ certificate
   sig_id = f"xmldsig-{cert.serial_number}"

   # กำหนด namespaces
   NSMAP = {
       'ds': 'http://www.w3.org/2000/09/xmldsig#',
       'xades': 'http://uri.etsi.org/01903/v1.3.2#',
       'xades141': 'http://uri.etsi.org/01903/v1.4.1#'
   }

   # สร้าง Signature element
   signature = etree.SubElement(root, "{http://www.w3.org/2000/09/xmldsig#}Signature", Id=sig_id, nsmap=NSMAP)

   # สร้าง SignedInfo
   signed_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")
   # กำหนด Canonicalization Method
   etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod",
                    Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
   # กำหนด Signature Method
   etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod",
                    Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")

   # สร้าง Reference สำหรับเอกสาร
   ref = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference",
                          Id=f"{sig_id}-ref0", URI="")
   transforms = etree.SubElement(ref, "{http://www.w3.org/2000/09/xmldsig#}Transforms")
   # กำหนด Transform สำหรับ enveloped signature
   etree.SubElement(transforms, "{http://www.w3.org/2000/09/xmldsig#}Transform",
                    Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
   # กำหนด DigestMethod
   etree.SubElement(ref, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")

   # สร้าง Reference สำหรับ SignedProperties
   ref_props = etree.SubElement(signed_info, "{http://www.w3.org/2000/09/xmldsig#}Reference",
                                Type="http://uri.etsi.org/01903#SignedProperties",
                                URI=f"#{sig_id}-signedprops")
   etree.SubElement(ref_props, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")

   # สร้าง SignatureValue
   sig_val = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}SignatureValue",
                              Id=f"{sig_id}-sigvalue")

   # สร้าง KeyInfo สำหรับเก็บ certificate
   key_info = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")
   x509_data = etree.SubElement(key_info, "{http://www.w3.org/2000/09/xmldsig#}X509Data")
   x509_cert = etree.SubElement(x509_data, "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
   x509_cert.text = cert_b64

   # สร้าง Object และ QualifyingProperties
   ds_object = etree.SubElement(signature, "{http://www.w3.org/2000/09/xmldsig#}Object")
   qualifying_props = etree.SubElement(ds_object, "{http://uri.etsi.org/01903/v1.3.2#}QualifyingProperties",
                                       Target=f"#{sig_id}")

   # สร้าง SignedProperties
   signed_props = etree.SubElement(qualifying_props, "{http://uri.etsi.org/01903/v1.3.2#}SignedProperties",
                                   Id=f"{sig_id}-signedprops")
   signed_sig_props = etree.SubElement(signed_props, "{http://uri.etsi.org/01903/v1.3.2#}SignedSignatureProperties")

   # เพิ่มเวลาที่เซ็น
   signing_time = etree.SubElement(signed_sig_props, "{http://uri.etsi.org/01903/v1.3.2#}SigningTime")
   signing_time.text = datetime.now(pytz.timezone('Asia/Bangkok')).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"+07:00"

   # เพิ่มข้อมูล certificate
   signing_cert = etree.SubElement(signed_sig_props, "{http://uri.etsi.org/01903/v1.3.2#}SigningCertificate")
   cert_ref = etree.SubElement(signing_cert, "{http://uri.etsi.org/01903/v1.3.2#}Cert")

   # สร้าง CertDigest
   cert_digest = etree.SubElement(cert_ref, "{http://uri.etsi.org/01903/v1.3.2#}CertDigest")
   etree.SubElement(cert_digest, "{http://www.w3.org/2000/09/xmldsig#}DigestMethod",
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha512")
   cert_digest_value = etree.SubElement(cert_digest, "{http://www.w3.org/2000/09/xmldsig#}DigestValue")

   # เพิ่มข้อมูลผู้ออก certificate
   issuer_serial = etree.SubElement(cert_ref, "{http://uri.etsi.org/01903/v1.3.2#}IssuerSerial")
   issuer_name = etree.SubElement(issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509IssuerName")
   issuer_name.text = cert.issuer.rfc4514_string()
   serial_number = etree.SubElement(issuer_serial, "{http://www.w3.org/2000/09/xmldsig#}X509SerialNumber")
   serial_number.text = str(cert.serial_number)

   # คำนวณ digest values
   signed_props_xml = etree.tostring(signed_props, method='c14n')
   doc_xml = etree.tostring(root, method='c14n')

   signed_props_hash = hashlib.sha512(signed_props_xml).digest()
   doc_hash = hashlib.sha512(doc_xml).digest()
   cert_hash = hashlib.sha512(cert_data).digest()

   # เพิ่ม digest values
   etree.SubElement(ref_props, "{http://www.w3.org/2000/09/xmldsig#}DigestValue").text = base64.b64encode(signed_props_hash).decode()
   etree.SubElement(ref, "{http://www.w3.org/2000/09/xmldsig#}DigestValue").text = base64.b64encode(doc_hash).decode()
   cert_digest_value.text = base64.b64encode(cert_hash).decode()

   # เซ็นเอกสารด้วย HSM
   signed_info_c14n = etree.tostring(signed_info, method='c14n')
   signature_value = sign_with_safenet(signed_info_c14n)
   sig_val.text = base64.b64encode(signature_value).decode()

   return root

# เรียกใช้ฟังก์ชัน
signed_root = create_xades_signature("template.xml", "certificate.pem")
# บันทึกไฟล์ผลลัพธ์
with open("signed.xml", "wb") as f:
   f.write(etree.tostring(signed_root, encoding='utf-8', pretty_print=True))