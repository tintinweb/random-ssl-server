# -*- coding: utf-8 -*-
'''
Created on 31.07.2013

@author: martin
'''
import time
from M2Crypto import X509, EVP, RSA, ASN1
 

class Cert(object):        
    version = 3
    serial_number = 1
    signature_algorithm = 'rsa'
    signature_hash_algorithm = 'sha1'
    keybits = 1024
    valid_days = 365
    subject = None
    extensions = []
    
    privkey = None
    pubkey = None
    _cert = None
    _request = None
    
    
    def __init__(self):
        self.subject= X509.X509_Name()
        self._cert= X509.X509()
        self._csr = X509.Request()
        
    def make_csr(self):
        pk = EVP.PKey()
        
        if self.signature_algorithm.lower()=="rsa":
            rsa = RSA.gen_key(self.keybits, 65537, lambda: None)
            pk.assign_rsa(rsa)
            self._csr.set_pubkey(pk)
        
        self._csr.set_subject(self.subject)
        self._csr.sign(pk,self.signature_hash_algorithm)
        
        self.privkey = pk
        self.pubkey = self._csr.get_pubkey()
        return self._csr, pk  
        
    
    def make_cert(self):
        self._cert.set_serial_number(self.serial_number)
        self._cert.set_version(self.version)
        self._cert.set_subject(self.subject)
        self._cert.set_pubkey(self.privkey)
        self.add_expiration()
        for name,value in self.extensions:
            if value == "%%INSERT_FINGERPRINT%%":
                value = self._cert.get_fingerprint()
            self._cert.add_ext(X509.new_extension(name,value))        

        pass
    
    def sign(self, cert):
        if isinstance(cert,Cert):
            cert = cert._cert
        cert.set_issuer(self.subject)
        return cert.sign(self.privkey,self.signature_hash_algorithm)
        
        
    
    def add_expiration(self):
        t = long(time.time())
        now = ASN1.ASN1_UTCTIME()
        now.set_time(t)
        expire = ASN1.ASN1_UTCTIME()
        expire.set_time(t + self.valid_days * 24 * 60 * 60)
        self._cert.set_not_before(now)
        self._cert.set_not_after(expire)  
        
    def save(self,filename):
        with open(filename, 'w') as f:
            f.write(self._cert.as_pem())
            f.write(self.privkey.as_pem(None))
            
            
            

if __name__ == "__main__":
    ca = Cert()
    ca.subject.C = "AT"
    ca.subject.CN = "CA_Certificate"
    ca.subject.ST = 'X'
    ca.subject.L = 'XYZ_Location'
    ca.subject.O = 'CA_Org'
    ca.subject.OU = 'CA_OrgUnit'
    ca.extensions.append(('basicConstraints', 'CA:TRUE'))
    ca.extensions.append(('subjectKeyIdentifier', '%%INSERT_FINGERPRINT%%'))
    ca.make_csr()
    ca.make_cert()
    print ca.sign(ca)

    
    
    server_cert = Cert()
    server_cert.subject.C = "XY"
    server_cert.subject.CN = "موقع.وزارة-الاتصالات.مصر"
    server_cert.subject.ST = 'TT'
    server_cert.subject.O = 'Rogue'
    server_cert.subject.OU = 'RogueUnit'
    server_cert.extensions.append(('nsComment', 'SSL sever'))
    server_cert.make_csr()
    server_cert.make_cert()


    print ca.sign(server_cert)
    print server_cert._cert.as_pem()

    print server_cert._cert.verify(), server_cert._cert.check_ca()