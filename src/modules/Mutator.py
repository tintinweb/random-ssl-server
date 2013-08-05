# -*- coding: utf-8 -*-
'''
Created on 31.07.2013

@author: martin
'''
import string
import random

from rstr.rstr_base import Rstr
Generator = Rstr()

class CertMutateExplicit(object):

    fieldmap = {'version':'int',
               'serial_number':'int',
               'signature_algorithm':['rsa'],
               'signature_hash_algorithm':['sha1','md5'],
               'keybits':'int',
               'valid_days':'int',
               'subject':{ 'C': "string",
                           'CN': "string",
                           'ST': "string",
                           'O': 'string',
                           'OU': 'string',
                        }
                ,
                
               'extensions':{'nsComment':'stringRex',
                             'subjectKeyIdentifier':'hex',
                             'basicConstraints':'stringRex',       #CA:TRUE,pathlen:0,..
                             'keyUsage':'stringRex',               #keyUsage=digitalSignature, nonRepudiation
                             'extendedKeyUsage':'stringRex',       #extendedKeyUsage=critical,codeSigning,1.2.3.4
                             'authorityKeyIdentifier':'stringRex', #authorityKeyIdentifier=keyid,issuer
                             'subjectAltName':'stringRex',         #subjectAltName=email:copy,email:my@other.address,URI:http://my.url.here/
                             'issuserAltName':'stringRex',         #issuserAltName = issuer:copy
                             'crlDistributionPoints':'stringRex',  # crlDistributionPoints=URI:http://myhost.com/myca.crl
                             'issuingDistributionPoint':'stringRex',#
                             'policyConstraints':'stringRex',
                             'inhibitAnyPolicy':'stringRex',
                             'nameConstraints':'stringRex',
                             'noCheck':'stringRex',
                             '1.2.3.4':'stringRex',
                             },
               
               }
    
    def __init__(self,cert):
        self.cert = cert
        
    def mutate(self):
        # randomly select some fields
        keys = self.fieldmap.keys()
        for i in range(random.randint(0,len(keys))):
            # select up to all elements :p
            k = random.choice(keys)
            v = self.fieldmap[k]        # type
            
            if isinstance(v,basestring):
                if v in ['int','string']:
                    fuzzval = getattr(self,"fuzz_%s"%v)()
            elif isinstance(v,list):
                fuzzval = random.choice(v)
            elif isinstance(v,dict):
                # pick random number of fields
                fuzzval = {}
                kk = v.keys()
                for ii in range(random.randint(1,len(kk))):

                    rnd_k = random.choice(kk)
                    rnd_v = v[rnd_k]
                    if isinstance(rnd_v,basestring):
                        if rnd_v in ['int','string']:
                            fzzval = getattr(self,"fuzz_%s"%rnd_v)()
                            fuzzval[rnd_k]=fzzval
                            
                
                
                # fix vals for subject
                if k == "extensions":
                    fuzzval = [(rnd_k,fval) for rnd_k,fval in fuzzval.iteritems()]
                    setattr(self.cert,k,fuzzval)
                elif k == "subject":
                    for kkk,vvv in fuzzval.iteritems():
                        setattr(self.cert.subject,kkk,vvv)
                else:
                    setattr(self.cert,k,fuzzval)
                    
                
            
            
            print "fuzzing: %s = %s"%(k,fuzzval)
            #print "fuzzing: %s"%k
        return self.cert
    
    def special(self):
        patterns = ['.',
              '..',
              '\\',
              '/',   
              '*',
              '%',
              '*:*',             
              ] 
        pass
    def get_quot(self,data):
        modifier =  ["%s",
                     '"%s"',
                     "'%s'",
                     "`%s`"]
        for m in modifier:
            yield m%data

    def fuzz_string(self, size=24, chars=string.ascii_letters+string.digits):
        if random.choice([0,1]):
            return (''.join(random.choice(chars) for x in range(size)))
        return self.fuzz_ustring(size)
    
    def fuzz_ustring(self,size=24):
        #+u'关于调整部分增值服务内容的公告关于7月30日早间外汇宝、双向宝挂单功能暂停的公告关于开展个人人民币存款账户身份信息真实性核实工作的公告'+u'بار عربية عاجلة وبث حي لقناة الجزيرة, جولة في الصحافة ومقالات وتحليلات, أخبار سياسية واقتصادية ورياضية وثقافية وحقوقية, تغطيات خاصة, و آخر أحداث عالم الطب ...'
        return (''.join((unichr(random.choice((0x300, 0x2000)) + random.randint(0, 0xff))) for x in range(size)))
        return 
    
    def fuzz_stringRex(self, size=6, chars=string.ascii_letters+string.digits):
        return ''.join(random.choice(chars) for x in range(size))
    
    def fuzz_int(self,min=-2049,max=2049):
        return random.randrange(min,max)
    
    
 
    def createPatternCyclic(self,size):
         
         char1="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
         char2="abcdefghijklmnopqrstuvwxyz"
         char3="0123456789"
         
         charcnt=0
         pattern=""
         max=int(size)
         while charcnt < max:
             for ch1 in char1:
                 for ch2 in char2:
                     for ch3 in char3:
                         if charcnt<max:
                             pattern=pattern+ch1
                             charcnt=charcnt+1
                         if charcnt<max:
                             pattern=pattern+ch2
                             charcnt=charcnt+1
                         if charcnt<max:
                             pattern=pattern+ch3
                             charcnt=charcnt+1
         return pattern    
     
     
class CertMutateRegex(object):

    fieldmap = {'version':r'-?\d{1,6}',
               'serial_number':r'\d{1,10}',
               'signature_algorithm':['rsa'],
               'signature_hash_algorithm':['sha1','md5'],
               'keybits':r'[1-4]\d{2,3}',
               'valid_days':r'\d{1,4}',
               'subject':{ 'C': r"\w{2}",
                           'CN': r"\w{1,9}\.([\x01-\xfe]+)?\w{2,9}\.\w{2,4}",
                           'ST': r"[\w\s\d\-_\.]{0,300}",
                           'O': r'[\w\s\d\-_\.]{0,300}',
                           'OU': r'[\w\s\d\-_\.]{0,300}',
                        }
                ,
                
               'extensions':{'nsComment':r'(SSL Server )?[\w\s\d\-_\.]{1,255}',
                             'subjectKeyIdentifier':'[\x00-\xff]{16}',
                             'basicConstraints':r'(CA:[\w\s\d\-_\.]{1,255})?(,pathlen:\d{0,10})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',       #CA:TRUE,pathlen:0,..
                             'keyUsage':r'(keyUsage=[\w\s\d\-_\.]{1,255})?(,nonRepudiation=[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',               #keyUsage=digitalSignature, nonRepudiation
                             'extendedKeyUsage':r'(extendedKeyUsage=(critical)?(,codeSigning)?(,1.2.3.4)?[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',       #extendedKeyUsage=critical,codeSigning,1.2.3.4
                             'authorityKeyIdentifier':r'(authorityKeyIdentifier=[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?', #authorityKeyIdentifier=keyid,issuer
                             'subjectAltName':r'(subjectAltName=(email|URI):[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',         #subjectAltName=email:copy,email:my@other.address,URI:http://my.url.here/
                             'issuserAltName':r'(issuserAltName=[\w\s\d\-_\.]{1,255}:[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',         #issuserAltName = issuer:copy
                             'crlDistributionPoints':r'(crlDistributionPoints=URL:http://[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',  # crlDistributionPoints=URI:http://myhost.com/myca.crl
                             'issuingDistributionPoint':r'(\w{0,30}=[\w\s\d\-_\.]{1,255})?',#
                             'policyConstraints':r'(\w{0,30}=[\w\s\d\-_\.]{1,255})?',
                             'inhibitAnyPolicy':r'(\w{0,30}=[\w\s\d\-_\.]{1,255})?',
                             'nameConstraints':r'(\w{0,30}=[\w\s\d\-_\.]{1,255})?',
                             'noCheck':r'(,authorityKeyIdentifier=[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',
                             '1.2.3.4':r'(,authorityKeyIdentifier=[\w\s\d\-_\.]{1,255})?(,\w{0,30}=[\w\s\d\-_\.]{1,255})?',
                             },
               
               }
    
    def __init__(self,cert):
        self.cert = cert
        
    def mutate(self,root=None, definition=None):
        definition = definition or self.fieldmap
        # randomly select some fields
        keys = definition.keys()
        for i in range(random.randint(0,len(keys))):
            fuzzval = None
            # select up to all elements :p
            k = random.choice(keys)
            v = definition[k]        # type
            
            if isinstance(v,basestring):
                # check if there's a function handling this type
                try:
                    fuzzval = getattr(self,"fuzz_%s"%v)()
                except:
                    pass
                # use regex generator
                fuzzval = Generator.xeger(v)
            elif isinstance(v,list):
                fuzzval = random.choice(v)
            elif isinstance(v,dict):
                # pick random number of fields
                self.mutate(root=k,definition=v)
                # end execution, everything isdone within mutate
                return

            # fix vals for subject
            if fuzzval:
                if root == "extensions":
                    #fuzzval = [(rnd_k,fval) for rnd_k,fval in fuzzval.iteritems()]
                    self.cert.extensions.append((k,fuzzval))
                    #setattr(self.cert,k,fuzzval)
                elif root == "subject":
                    setattr(self.cert.subject,k,fuzzval)
                else:
                    # handle int/long/... with self.convert
                    fuzzval=self.convert(getattr(self.cert,k), fuzzval)
                    setattr(self.cert,k,fuzzval)
            
            print "Mutating: %s = %s"%(k,repr(fuzzval))
            #print "fuzzing: %s"%k
        return self.cert
    
    def convert(self,key,value):
        return type(key)(value)
            
    

     
     
if __name__ == "__main__":    
    from Certificate import Cert
    server_cert = Cert()
    server_cert.subject.C = "XY"
    server_cert.subject.CN = "موقع.وزارة-الاتصالات.مصر"
    server_cert.subject.ST = 'TT'
    server_cert.subject.O = 'Rogue'
    server_cert.subject.OU = 'RogueUnit'
    server_cert.extensions.append(('nsComment', 'SSL sever'))
    server_cert.make_csr()
    server_cert.make_cert()
    
    fuzz_server_cert = CertMutateRegex(server_cert)
    fuzz_server_cert.mutate()
    print server_cert._cert.verify()
 