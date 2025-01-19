from PyKCS11 import *

pkcs11 = PyKCS11Lib()
pkcs11.load(r"C:\Windows\System32\eToken.dll")
slots = pkcs11.getSlotList()

for slot in slots:
   try:
       session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
       session.login("your_pin")  # ใส่ PIN token

       # ดึง certificates
       certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
       if certs:
           print(f"\nSlot {slot}:")
           for cert in certs:
               label = session.getAttributeValue(cert, [CKA_LABEL])[0]
               print(f"- Certificate: {label}")

       # ดึง private keys
       private_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY)])
       if private_keys:
           for key in private_keys:
               label = session.getAttributeValue(key, [CKA_LABEL])[0]
               print(f"- Private Key: {label}")

   except PyKCS11.PyKCS11Error as e:
       print(f"Error on slot {slot}: {str(e)}")
       continue