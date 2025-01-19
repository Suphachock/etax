from PyKCS11 import *

pkcs11 = PyKCS11Lib()
pkcs11.load(r"C:\Windows\System32\eToken.dll")
slots = pkcs11.getSlotList()

for slot in slots:
    try:
        session = pkcs11.openSession(slot)
        certs = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])
        if certs:
            print(f"Slot {slot}:")
            for cert in certs:
                label = session.getAttributeValue(cert, [CKA_LABEL])[0]
                print(f"- Certificate: {label}")
    except:
        continue