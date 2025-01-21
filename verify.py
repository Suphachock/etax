from signxml import XMLVerifier
from lxml import etree
import base64
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from datetime import datetime

def verify_xml_signature_detailed(signed_xml_path, cert_path=None):
    """
    ตรวจสอบ XML digital signature พร้อมแสดงรายละเอียด
    
    Args:
        signed_xml_path (str): ไฟล์ XML ที่มีลายเซ็น
        cert_path (str, optional): ไฟล์ certificate ถ้ามี
    
    Returns:
        dict: ผลการตรวจสอบพร้อมรายละเอียด
    """
    result = {
        "is_valid": False,
        "verification_time": datetime.now().isoformat(),
        "details": [],
        "errors": [],
        "certificate_info": {},
        "signature_info": {}
    }
    
    try:
        # อ่านไฟล์ XML
        result["details"].append("1. กำลังอ่านไฟล์ XML")
        with open(signed_xml_path, 'rb') as f:
            signed_xml = f.read()
            
        # ตรวจสอบรูปแบบ XML
        try:
            etree.fromstring(signed_xml)
            result["details"].append("2. รูปแบบ XML ถูกต้อง")
        except etree.XMLSyntaxError as e:
            result["errors"].append(f"XML syntax ไม่ถูกต้อง: {str(e)}")
            return result
            
        verifier = XMLVerifier()
        
        if cert_path:
            result["details"].append("3. กำลังใช้ certificate ภายนอก")
            try:
                with open(cert_path, 'rb') as f:
                    cert_data = f.read()
                cert = load_pem_x509_certificate(cert_data)
                
                # ตรวจสอบวันหมดอายุของ certificate
                current_time = datetime.now()
                if current_time < cert.not_valid_before or current_time > cert.not_valid_after:
                    result["errors"].append(f"Certificate หมดอายุหรือยังไม่ถึงวันใช้งาน: \nวันเริ่มต้น: {cert.not_valid_before}\nวันหมดอายุ: {cert.not_valid_after}\nวันที่ปัจจุบัน: {current_time}")
                    return result
                
                # เก็บข้อมูล certificate
                result["certificate_info"] = {
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "not_valid_before": cert.not_valid_before.isoformat(),
                    "not_valid_after": cert.not_valid_after.isoformat(),
                    "serial_number": cert.serial_number,
                    "signature_algorithm": cert.signature_algorithm_oid._name
                }
                
                data = verifier.verify(
                    signed_xml,
                    x509_cert=cert,
                    expect_references=True
                )
            except Exception as e:
                result["errors"].append(f"เกิดข้อผิดพลาดในการอ่าน certificate: {str(e)}")
                return result
        else:
            result["details"].append("3. กำลังใช้ certificate ที่ฝังอยู่ใน XML")
            try:
                data = verifier.verify(
                    signed_xml,
                    expect_references=True
                )
            except Exception as e:
                result["errors"].append(f"เกิดข้อผิดพลาดในการตรวจสอบ signature: {str(e)}")
                return result
        
        # เก็บข้อมูล signature
        result["signature_info"] = {
            "signed_info": str(data.signed_info),
            "signature_method": str(data.signature_method),
            "canonicalization_method": str(data.canonicalization_method),
            "reference_uris": [str(ref) for ref in data.reference_uris] if hasattr(data, 'reference_uris') else []
        }
        
        result["is_valid"] = True
        result["details"].append("4. ลายเซ็นถูกต้องและสมบูรณ์")
        
    except InvalidSignature:
        result["errors"].append("ลายเซ็นไม่ถูกต้อง")
    except Exception as e:
        result["errors"].append(f"เกิดข้อผิดพลาดที่ไม่คาดคิด: {str(e)}")
    
    return result

def print_verification_result(result):
    """
    แสดงผลการตรวจสอบในรูปแบบที่อ่านง่าย
    """
    print("\n=== ผลการตรวจสอบ XML Signature ===")
    print(f"เวลาที่ตรวจสอบ: {result['verification_time']}")
    print(f"สถานะ: {'✓ ถูกต้อง' if result['is_valid'] else '✗ ไม่ถูกต้อง'}")
    
    print("\n--- ขั้นตอนการตรวจสอบ ---")
    for detail in result["details"]:
        print(f"✓ {detail}")
        
    if result["errors"]:
        print("\n--- ข้อผิดพลาดที่พบ ---")
        for error in result["errors"]:
            print(f"✗ {error}")
    
    if result["certificate_info"]:
        print("\n--- ข้อมูล Certificate ---")
        for key, value in result["certificate_info"].items():
            print(f"{key}: {value}")
    
    if result["signature_info"]:
        print("\n--- ข้อมูล Signature ---")
        for key, value in result["signature_info"].items():
            print(f"{key}: {value}")

# ตัวอย่างการใช้งาน
if __name__ == "__main__":
    # ตัวอย่างการตรวจสอบโดยใช้ certificate ที่ฝังใน XML
    result = verify_xml_signature_detailed("999.xml")
    print_verification_result(result)
    
    # ตัวอย่างการตรวจสอบโดยใช้ certificate ภายนอก
    # result = verify_xml_signature_detailed(
    #     "signed_document.xml",
    #     "public_cert.pem"
    # )
    print_verification_result(result)