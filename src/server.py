# -*- coding: utf-8 -*-
'''
Created on 31.07.2013

@author: martin
'''
# need to import M2Crypto here in order to fix strange exception (dll load failed)
from M2Crypto import X509, EVP, RSA, ASN1
from modules.HttpsServer import SecureHTTPServer
from modules.Certificate import Cert
from modules.Mutator import CertMutateRegex


def generate_cert(filename):
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
    #print ca.sign(ca)

    
    
    server_cert = Cert()
    server_cert.subject.C = "XY"
    server_cert.subject.CN = "موقع.وزارة-الاتصالات.مصر"
    server_cert.subject.ST = 'TT'
    server_cert.subject.O = 'Rogue'
    server_cert.subject.OU = 'RogueUnit'
    server_cert.extensions.append(('nsComment', 'SSL sever'))

    CertMutateRegex(server_cert).mutate()
    
    server_cert.make_csr()
    server_cert.make_cert()
    
    #fuzzer = CertMutateRegex(server_cert)
    #fuzzer.mutate()
    #server_cert.make_csr()
    #server_cert.make_cert()

    ca.sign(server_cert)
    #print server_cert._cert.as_pem()
    server_cert.save(filename)

    print " [i] Integrity: %s  (is_CA:%s)"%('ok' if server_cert._cert.verify() else 'not-ok!', 'yes' if server_cert._cert.check_ca() else 'no')




      

if __name__ == "__main__":
    server_address = ('', 443) # (address, port)
    httpd = SecureHTTPServer(server_address)
    httpd.setup_socket()
    sa = httpd.socket.getsockname()
    print "[i] Serving HTTPS on", sa[0], "port", sa[1], "..."
    while True:
        print "[ ] --new--"
        generate_cert('cert.pem')
        httpd.sslify('cert.pem')
        print "[+] ready ..."
        try:
            httpd.handle_request()
        except:
            pass
            
        
