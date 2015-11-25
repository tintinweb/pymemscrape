#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

import sys, os, re
import binascii
import ctypes
import re
import mmap
import pyasn1

FAIL = True
PASS = False

class SkipException(Exception): pass
class DoesNotValidateException(Exception): pass

def ctype_to_str(t):
    t = ''.join(re.findall(r'c_([\w\d_*]+)',str(t)))
    return t.replace("_p","*")

class CStruct(ctypes.Structure):
    name = "--unknown--"
    @classmethod
    def from_template(cls, tpl):
        return cls.class_from_template(tpl)()
    @classmethod
    def class_from_template(cls, tpl):
        return type(tpl.__class__.__name__, (CStruct,), 
                    {"_fields_": [tuple(f[:2]) for f in tpl._rules_],
                     "_rules_": tpl._rules_,
                     "name":tpl.name})
        
    def class_from_cstruct(self, cstruct):
        name = ''.join(re.findall("typedef struct ([\w\d_]+)\w{"))
    
    def from_bytes(self, bytes):
        fit = min(len(bytes), ctypes.sizeof(self))
        ctypes.memmove(ctypes.addressof(self), bytes, fit)
        return fit
    
    def to_bytes(self):
        return buffer(self)[:]
    
    def __len__(self):
        return len(self.to_bytes())
    
    def __str__(self, *args, **kwargs):
        return self.as_cstruct()
    
    def as_str(self):
        s = []
        s.append("struct %s "%self.name)
        for k,t in self._fields_:
            val = getattr(self,k)
            if val and t==ctypes.c_void_p:
                val = hex(val)
            s.append("%-30s: %s"%(repr(k),repr(val)))
        return '\n'.join(s)
    
    def as_cstruct(self):
        s = []
        s.append("struct %s {"%self.name)
        for k,t in self._fields_:
            val = getattr(self,k)
            if val and t==ctypes.c_void_p:
                val = hex(val)
            s.append("    %-15s %s = %s"%(ctype_to_str(t), k,repr(val)))
        s+="}"
        return '\n'.join(s)
    
    def is_valid(self, mem=None):
        for rule in self._rules_:
            validation = []
            if len(rule)==2:
                name, typ = rule
                #if typ in (ctypes.c_void_p, ctypes.c_char_p):
                #    validation.append(Validate.is_ptr)
                    
            elif len(rule)==3:
                name, typ, validation_rules = rule
                if isinstance(validation_rules, basestring):
                    validation_rules = [validation_rules]
                for v in validation_rules:
                    if isinstance(v, basestring):
                        validation.append(lambda obj,mem,val: PASS if val==v else FAIL)
                    else:
                        validation.append(v)
                    
            else:
                raise Exception("Invalid! rule must be either <name,type> or <name,type,validation>: %s"%repr(rule))
            val = getattr(self, name)
            
            if any(v(val,self,mem) for v in validation):
                #raise DoesNotValidateException("DoesNotValidate: %s %s %s"%(repr(name),repr(typ),repr(val)))
                return False
            print name, repr(val)
        return True
            
            
        
'''
struct rsa_st {
    /*
     * The first parameter is used to pickup errors where this is passed
     * instead of aEVP_PKEY, it is set to 0
     */
    int pad;
    long version;
    const RSA_METHOD *meth;
    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    /* be careful using this if the RSA structure is shared */
    CRYPTO_EX_DATA ex_data;
    int references;
    int flags;
    /* Used to cache montgomery values */
    BN_MONT_CTX *_method_mod_n;
    BN_MONT_CTX *_method_mod_p;
    BN_MONT_CTX *_method_mod_q;
    /*
     * all BIGNUM values are actually in the following data, if it is not
     * NULL
     */
    char *bignum_data;
    BN_BLINDING *blinding;
    BN_BLINDING *mt_blinding;
};
'''
   
class Validate(object):
    @staticmethod
    def not_null(val, obj, mem=None):
        if val==None or val==0:
            return FAIL
        return PASS
    @staticmethod
    def is_null(val, obj, mem=None):
        if val==0:
            return PASS
        return FAIL
    @staticmethod
    def is_ptr(val, obj, mem=None):
        if val == 0:
            return FAIL     # want valid ptrs
        elif val == None:
            return FAIL
        elif 0 < val and val < 4096:
            return FAIL    # protected page
        elif val & (0xff << 2*4*(ctypes.sizeof(ctypes.c_void_p)-1)):
            return FAIL    # top byte set
        if mem==None:
            return PASS
        #print "is_ptr memcheck", repr(mem.get_region_by_address(val))
        return PASS if mem.get_region_by_address(val) else FAIL
    @staticmethod
    def ignore(val, obj, mem=None):
        return PASS
    @staticmethod
    def is_bignum_st(val, obj, mem=None):
        if not val:
            return FAIL
        bignum = CStruct.from_template(bignum_st())
        r = mem.get_data_at_address(val,8*1024)
        if not r:
            return FAIL
        try:
            bignum = CStruct.class_from_template(bignum_st).from_buffer(r)
        except ValueError,ve:
            return FAIL
        #bignum.from_bytes()
        
        ret= bignum.is_valid(mem=mem)
        return PASS
    @staticmethod
    def is_ec_point_st(val, obj, mem=None):
        if not val:
            return FAIL
        ec_point = CStruct.from_template(ec_point_st())
        r = mem.get_data_at_address(val,8*1024)
        if not r:
            return FAIL
        try:
            ec_point = CStruct.class_from_template(ec_point_st).from_buffer(r)
        except ValueError,ve:
            return FAIL
        #bignum.from_bytes()
        
        ret= ec_point.is_valid(mem=mem)
        return PASS
#http://h71000.www7.hp.com/doc/83final/ba554_90007/apas05.html
SSL_MAX_KEY_ARG_LENGTH= 8
SSL_MAX_MASTER_KEY_LENGTH =       48
SSL_MAX_SSL_SESSION_ID_LENGTH = 32
SSL_MAX_SID_CTX_LENGTH = 32

PROTO_SSL_2_0 = 0x0002
PROTO_SSL_3_0 = 0x0300
PROTO_TLS_1_0 = 0x0301
PROTO_TLS_1_1 = 0x0302
PROTO_TLS_1_2 = 0x0303
PROTO_DTLS_1_0_OPENSSL_PRE_0_9_8f = 0x0100
PROTO_DTLS_1_0 = 0xfeff
PROTO_DTLS_1_1 = 0xfefd

class ssl_session_st(CStruct):
    name = "ssl_session_st"
    _rules_ = [
                ("version", ctypes.c_int, [lambda val,obj,mem: PASS if val in (PROTO_SSL_2_0,PROTO_DTLS_1_0_OPENSSL_PRE_0_9_8f,PROTO_DTLS_1_0,PROTO_DTLS_1_1) or (val > 700 and val < 1000) else FAIL]),
                ("key_arg_length", ctypes.c_uint,),# [lambda val,obj,mem: PASS if val==SSL_MAX_KEY_ARG_LENGTH else FAIL]),
                ("key_arg", ctypes.c_char*SSL_MAX_KEY_ARG_LENGTH,[lambda val,obj,mem: PASS if len(val)==obj.key_arg_length else FAIL]),
                ("master_key_length", ctypes.c_int, [Validate.not_null]),
                ("master_key", ctypes.c_char*SSL_MAX_MASTER_KEY_LENGTH, [lambda val,obj,mem: PASS if len(val)==obj.master_key_length else FAIL]),
                ("session_id_length",ctypes.c_int, ),
                ("session_id",ctypes.c_char*SSL_MAX_SSL_SESSION_ID_LENGTH,[lambda val,obj,mem: PASS if len(val)==obj.session_id_length else FAIL]),
                ("sid_ctx_length",ctypes.c_int),
                ("sid_ctx",ctypes.c_char*SSL_MAX_SID_CTX_LENGTH),
                ("not_resumable",ctypes.c_int),
                ("sess_cert",ctypes.c_void_p),
                ("peer",ctypes.c_void_p),
                ("verify_result",ctypes.c_long),
                ("references",ctypes.c_int), #[Validate.not_null]),
                ("timeout",ctypes.c_long),
                ("time",ctypes.c_long),
                ("compress_meth",ctypes.c_int),
                ("cipher",ctypes.c_void_p),
                ("cipher_id",ctypes.c_ulong),
                ("ciphers",ctypes.c_void_p),
                #("ex_data_sk",ctypes.c_void_p),
                #("ex_data_dummy",ctypes.c_int),
                #("prev",ctypes.c_void_p),
                #("next",ctypes.c_void_p),
                ]

class bignum_st(CStruct):
    name = "bignum_st"
    _rules_ = [
                ("d", ctypes.c_void_p),
                ("top", ctypes.c_int),
                ("dmax", ctypes.c_int),# [Validate.not_null]),
                ("neg", ctypes.c_int, [lambda val,obj,mem: PASS if (val==1 or val==0) else FAIL]),
                ("flags", ctypes.c_int),
                ]

class dsa_st(CStruct):
    name = "dsa_st"
    _rules_ = [
                ("pad", ctypes.c_int),
                ("version", ctypes.c_long, [lambda val, obj, mem: PASS if val==0 else FAIL]),
                ("write_params", ctypes.c_int),
                #
                ("p", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.q else PASS, Validate.is_bignum_st]),
                ("q", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.p else PASS, Validate.is_bignum_st]),
                ("g", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.q else PASS, Validate.is_bignum_st]),
                #
                ("pub_key", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.pub_key else PASS, Validate.is_bignum_st]),
                ("priv_key", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.priv_key else PASS, Validate.is_bignum_st]),
                #
                ("kinv", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.r else PASS, Validate.is_bignum_st]),
                ("r", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.kinv else PASS, Validate.is_bignum_st]),
                #
                #("flags", ctypes.c_int),
                #("method_mont_p", ctypes.c_void_p),
                #("references", ctypes.c_void_p, [Validate.not_null]),
                #
                #("ex_data_sk", ctypes.c_void_p),
                #("ex_data_dummy", ctypes.c_int),
                #
                #("meth", ctypes.c_void_p),
                #("engine", ctypes.c_void_p),
                #
                ]

class rsa_st(CStruct):
    name = "rsa_st"
    _rules_ = [
                ("pad", ctypes.c_int),
                ("version", ctypes.c_long , [lambda val, obj, mem: PASS if val==0 else FAIL]),  # typically 0 acc. to RSA_new_method
                ("meth", ctypes.c_void_p),
                #
                ("engine", ctypes.c_void_p),
                #("n", ctypes.c_void_p, [lambda val, obj, mem: FAIL if any(val==c for c in (obj.e,obj.d,obj.p,obj.q,obj.dmp1,obj.dmq1,obj.iqmp)) else PASS, Validate.is_bignum_st]),
                ("n", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.e else PASS, Validate.is_bignum_st]),
                ("e", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.e else PASS, Validate.is_bignum_st]),
                ("d", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.e else PASS, Validate.is_bignum_st]),
                ("p", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.q else PASS, Validate.is_bignum_st]),
                ("q", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.p else PASS, Validate.is_bignum_st]),
                ("dmp1", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.e else PASS, Validate.is_bignum_st]),
                ("dmq1", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.e else PASS, Validate.is_bignum_st]),
                ("iqmp", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.e else PASS, Validate.is_bignum_st]),
                #
                #("ex_data", ctypes.c_void_p),#
                #("ex_data_sk", ctypes.c_void_p),
                #("ex_data_dummy", ctypes.c_int),
                #
                #("references", ctypes.c_void_p, [Validate.not_null]),
                #("flags", ctypes.c_void_p),
                #
                #("_method_mod_n", ctypes.c_void_p),
                #("_method_mod_p", ctypes.c_void_p),
                #("_method_mod_q", ctypes.c_void_p),
                #
                #("bignum_data", ctypes.c_void_p),
                #
                #("blinding", ctypes.c_void_p),
                #("mt_blinding", ctypes.c_void_p),
                ]
    
####
"""    ====== modules/ssl/ssl_private.h extract =========

    /** public cert/private key */
    typedef struct {
         /**
          * server only has 1-2 certs/keys
          * 1 RSA and/or 1 DSA
          */
         const char  *cert_files[SSL_AIDX_MAX];
         const char  *key_files[SSL_AIDX_MAX];
         X509        *certs[SSL_AIDX_MAX];
         EVP_PKEY    *keys[SSL_AIDX_MAX];           <===

         /** Certificates which specify the set of CA names which should be
          * sent in the CertificateRequest message: */
         const char  *ca_name_path;
         const char  *ca_name_file;
    } modssl_pk_server_t;
    ================================================="""
####   
class evp_pkey_st(CStruct):
    name = "evp_pkey_st"
    #http://openxdas.sourceforge.net/doxygen/html/evp_8h-source.html
    _rules_ = [
                ("type", ctypes.c_int),
                ("save_type", ctypes.c_int),
                ("references", ctypes.c_int, [Validate.not_null]),
                # union {
                ("ptr",ctypes.c_void_p),
                ("rsa",ctypes.c_void_p),
                ("dsa",ctypes.c_void_p),
                ("dh",ctypes.c_void_p),
                ("ec",ctypes.c_void_p),
                # } pkey
                ("save_parameters", ctypes.c_int),
                ("attributes", ctypes.c_void_p),
                ]

SSL_AIDX_MAX = 3
class modssl_pk_server_t(CStruct):
    name = "modssl_pk_server_t"
    _rules_ = [
                ("cert_files", ctypes.c_char_p*SSL_AIDX_MAX),
                ("key_files", ctypes.c_char_p*SSL_AIDX_MAX),

                ("certs", ctypes.c_void_p*SSL_AIDX_MAX),
                ("keys", ctypes.c_void_p*SSL_AIDX_MAX),

                ("ca_name_path", ctypes.c_char_p, Validate.not_null),
                ("ca_name_file", ctypes.c_char_p, Validate.not_null),
                ]
"""
https://fossies.org/dox/openssl-1.0.2d/ec__lcl_8h_source.html
struct ec_key_st {
  266     int version;
  267     EC_GROUP *group;
  268     EC_POINT *pub_key;
  269     BIGNUM *priv_key;
  270     unsigned int enc_flag;
  271     point_conversion_form_t conv_form;
  272     int references;
  273     int flags;
  274     EC_EXTRA_DATA *method_data;
  275 } /* EC_KEY */ ;
"""
POINT_CONVERSION_COMPRESSED = 2,
POINT_CONVERSION_UNCOMPRESSED = 4,
POINT_CONVERSION_HYBRID = 6
class ec_key_st(CStruct):
    name = "ec_key_st"
    _rules_ = [
                ("version", ctypes.c_int, [lambda val,obj,mem: PASS if val==1 else FAIL]), # usually 1
                ("group", ctypes.c_void_p),# [Validate.is_ptr]),
                ("pub_key", ctypes.c_void_p, [Validate.is_ptr,Validate.is_ec_point_st]),
  
                ("priv_key",ctypes.c_void_p, [Validate.is_ptr,Validate.is_bignum_st]),
                ("enc_flag",ctypes.c_uint),
                ("conv_form",ctypes.c_int, [lambda val,obj,mem: PASS if val in (POINT_CONVERSION_COMPRESSED,POINT_CONVERSION_UNCOMPRESSED,POINT_CONVERSION_HYBRID) else FAIL]),
                ("references",ctypes.c_int, [Validate.not_null, lambda val,obj,mem : PASS if val>0 else FAIL]),
                ("flags",ctypes.c_void_p),#[Validate.is_ptr]),
                
                ("ex_data_sk", ctypes.c_void_p),
                ("ex_data_dummy", ctypes.c_int),
                ]
    
class dh_st(CStruct):
    name = "dh_st"
    _rules_ = [
                ("pad", ctypes.c_int),
                ("version", ctypes.c_long , [lambda val, obj, mem: PASS if val==0 else FAIL]),  # typically 0 acc. to RSA_new_method
                #
                ("p", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.p else PASS, Validate.is_bignum_st]),
                ("q", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.q else PASS, Validate.is_bignum_st]),
                
                #
                ("length", ctypes.c_long),
                #
                ("pub_key", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.priv_key else PASS, Validate.is_bignum_st]),
                ("priv_key", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.pub_key else PASS, Validate.is_bignum_st]),
                #
                #("flags", ctypes.c_void_p),
                #("method_mont_p", ctypes.c_void_p),
                #("q", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.q else PASS, Validate.is_bignum_st]),
                #("j", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.j else PASS, Validate.is_bignum_st]),
                
                #
                #("seed", ctypes.c_char_p),
                #("seedlen", ctypes.c_int),
                #("counter", ctypes.c_void_p, [lambda val, obj, mem: FAIL if val==obj.p else PASS, Validate.is_bignum_st]),
                #("references", ctypes.c_int, [Validate.not_null]),
                #
                #("ex_data_sk", ctypes.c_void_p),
                #("ex_data_dummy", ctypes.c_int),
                #
                #("meth", ctypes.c_void_p),
                #("engine", ctypes.c_void_p),
                ]

class ec_point_st(CStruct):
    name = "ec_point_st"
    _rules_ = [
                ("meth", ctypes.c_void_p),
                ("X", ctypes.c_void_p, [Validate.is_bignum_st]),
                ("Y", ctypes.c_void_p, [Validate.is_bignum_st]),
                ("Z", ctypes.c_void_p, [Validate.is_bignum_st]),
                ("Z_is_one", ctypes.c_int,[lambda val,obj,mem: PASS if val==0 or val==1 else FAIL]),
                ]

class asn1sequence(object):
    def __init__(self):
        self.data = None
        self.asn1 = None
        self.length = 0
        
    def consume(self, data):
        if not data or not data[0]=='\x30':
            return False
        seq = data
        try:
            bytes_consumed=0
            prev_length = None
            prev_index = 0
            for _ in xrange(2):
                #print "aaa", prev_index
                o = ASN1Element()
                bytes_consumed = o.consume(seq[prev_index:])
                if not bytes_consumed:
                    raise SkipException("not ASN.1")
                #print "tag",o.tag
                #print "length",o.length
                if o.length < 10:
                    raise SkipException("too short")
                if prev_length and prev_length < o.length:
                    raise SkipException("element does not fit in sublement")
                prev_length = o.length
                prev_index += bytes_consumed
                if prev_index > len(seq):
                    raise SkipException("out of bounds")
            #print repr(seq[:200])
            o = ASN1Element(seq)
            self.asn1 = pyasn1.codec.der.decoder.decode(data[index:index+o.length+o.hdr_len])
            self.length =o.length+o.hdr_len
            self.data = data
            return self.length
        except (pyasn1.error.PyAsn1Error, IndexError), e:
            print repr(e)
        except SkipException, e:
            pass
        return False

class ASN1Element(object):
    TYPE_UNIVERSAL = 0x00
    TYPE_BIT_STRING = 0x03
    TYPE_OCTET_STRING = 0x04
    TYPE_OBJECT_IDENTIFIER = 0x06
    
    def __init__(self, data=None):
        self.tag = None
        self.length = None
        self.value = None
        self.hdr_len = None
        self.offset = None  # start offset
        self.value_in_context = None
        
        self.bitstring_unused_bits =None        # BITSTRING SPECIFIC (extra byte)
        if data:
            self.consume(data)

    def __repr__(self):
        val="n/A" if self.get_tag_pc() else self.value[:20]
        val_ctx="n/A"
        if self.tag == self.TYPE_OBJECT_IDENTIFIER:
            val_ctx = self.oid_decode(self.value)
        elif self.tag == self.TYPE_BIT_STRING:
            val_ctx = "unsused_bits: %d"%ord(self.bitstring_unused_bits)
        return "<ASN1 @%d tag=0x%x len=%d hdr_len=%d value=%s context=%s>"%(self.offset,self.tag,self.length,self.hdr_len,repr(val),val_ctx)
        #return str({'@':self.offset,'tag':"0x%x"%(self.tag),'hdr_len':self.hdr_len,'len':self.length,'value':self.value[:5]+"..."})
    
    def get_tag_class(self):
        return self.tag & 0b11000000
    def get_tag_pc(self):
        return self.tag & 0b00100000        #indicates sub_structure
    def get_tag_type(self):
        return self.tag & 0b00011111  
    def get_tag_try_anyway(self):
        # may contain sub-asn1 structures
        if self.tag in (self.TYPE_BIT_STRING,self.TYPE_OCTET_STRING, self.TYPE_UNIVERSAL):
            # encapsulating types
            return self.tag # inspect this for content
        return False

    def consume(self,data):
        seq = iter(str(data))

        try:
            self.hdr_len=0
            tag = seq.next()
        except StopIteration:
            return {}  

        if ord(tag) & 0x1f == 0x1f:
            tag += seq.next()
            while ord(tag[-1]) & 0x80 == 0x80: 
                tag += seq.next()
            
        self.hdr_len += len(tag)

        real_length = 0
        length = ord(seq.next())
        self.hdr_len += 1

        if length == 0x80:
            # indefinite length.. search for 0x00 0x00
            self.hdr_len+=1
        elif length & 0x80 == 0x80:
            if length & 0x7f > 8:
                return 0
            lendata = "".join([seq.next() for i in xrange(length & 0x7f)])
            length = int(binascii.b2a_hex(lendata), 16)
            real_length = length
            self.hdr_len += len(lendata)
        else:
            # short form
            real_length = length
        
            
        if len(tag)==1 and tag==self.TYPE_BIT_STRING:
            # consume bitstring unused bits
            print "consume extra 'unused bits' byte"
            self.bitstring_unused_bits=seq.next()
            self.hdr_len+=1
            real_length -=1                        # reduce payload length since unused_bits is part of header     
            
        self.tag = ord(tag) if len(tag)==1 else tag
        self.length = length
        self.real_length=real_length
        return self.hdr_len        
    
    def __len__(self):
        return self.length+self.hdr_len
    
    def oid_decode(self, value):
        # http://msdn.microsoft.com/en-us/library/bb540809%28v=vs.85%29.aspx
        '''
        The first two nodes of the OID are encoded onto a single byte. The first node is multiplied by the decimal 40 and the result is added to the value of the second node.
        Node values less than or equal to 127 are encoded on one byte.
        Node values greater than or equal to 128 are encoded on multiple bytes. Bit 7 of the leftmost byte is set to one. Bits 0 through 6 of each byte contains the encoded value.
        // STILL NOT WORKING CORRECTLY ..
        '''
        rv = ""
        prev_byte=None
        for i,b in enumerate(value):
            b=ord(b)
            if i==0:
                rv += "%d.%d"%(b/40,b%40)
            elif b>=0x80 or prev_byte!=None:
                #multibyte
                if prev_byte!=None:
                    # got 2nd byte
                    val =prev_byte & 0b01111111
                    val |= ((b &0b11111) << 7)
                    rv += ".%d"%(val)
                    prev_byte=None
                    
                else:
                    # this is first byte
                    prev_byte=b
            else:
                rv += ".%d"%b
        return rv



class LinuxProcMemory(object):
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    def __init__(self, pid):
        self.cache = {}
        self.is_ptraced = False
        self.pid = pid
        self.f_mem_path = "/proc/%s/mem" % pid
        self.f_mmap_path = "/proc/%s/maps" % pid
        print "OPEN - proc"
        with open(self.f_mmap_path, 'r') as f_mmap:
            self.mmap = f_mmap.read().strip()
        self.regions = sorted(list(self._get_regions()), key=lambda r:r.start)
        try:
            self.fullmem = open(self.f_mem_path, 'rb')
        except:
            print "failed to open memory - retrying with ptrace attached."
            self.ptrace(self.PTRACE_ATTACH, pid)
            self.fullmem = open(self.f_mem_path, 'rb')

    def __del__(self):
        if self.fullmem:
            self.fullmem.close()
        self.ptrace(self.PTRACE_DETACH, self.pid)

    def get_regions(self):
        for r in self.regions:
            yield r

    def _get_regions(self):
        for txt_region in self.mmap.split('\n'):
            try:
                yield LinuxMemRegion(txt_region, open(self.f_mem_path, 'rb'))
            except:
                print "Not a valid memregion",txt_region
            
    def get_region_by_address(self, ptr):
        for r in self.regions:
            if ptr >= r.start and ptr <= r.end:
                return r
            if ptr > r.end:         # it is sorted by start-addr, exit early
                break   
        return None
    
    def get_data_at_address(self, ptr, size):
        ''' caching strategy - mark on first hit, cache on second hit 
            memory / cpu tradeoff
        '''
        CACHE_MARK = False
        cache_hit = self.cache.get(ptr)
        if cache_hit!=None and cache_hit!=CACHE_MARK:
            #print "CACHE HIT",ptr
            return cache_hit
        self.fullmem.seek(ptr)
        try:
            ret = bytearray(self.fullmem.read(size))
            if cache_hit==CACHE_MARK:
                self.cache[ptr]=ret         # cache it
            else:
                #print "CACHE MARK", ptr
                self.cache[ptr]=CACHE_MARK  # mark for caching, next time
            return ret
        except IOError, io:
            self.cache[ptr]=bytearray()     # cache the error
        return bytearray()
    
    def ptrace(self, mode, pid):
        if self.is_ptraced and mode==self.PTRACE_ATTACH:
            print "ptrace - already attached."
            return
        elif not self.is_ptraced and mode==self.PTRACE_DETACH:
            print "ptrace - not attached."
            return
        c_ptrace = ctypes.CDLL("libc.so.6").ptrace
        c_pid_t = ctypes.c_int32 # This assumes pid_t is int32_t
        c_ptrace.argtypes = [ctypes.c_int, c_pid_t, ctypes.c_void_p, ctypes.c_void_p]
        op = ctypes.c_int(mode)
        c_pid = c_pid_t(pid)
        null = ctypes.c_void_p()
        err = c_ptrace(op, c_pid, null, null)
        if err != 0: raise SysError, 'ptrace', err
        
class LinuxMemRegion(object):
    def __init__(self, txt_region, f_mem, ptr=None):
        self.txt_region = txt_region
        self.f = f_mem
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-rwxp]+)', txt_region)
        if not m:
            raise Exception(txt_region)
        start, end, perm = m.groups()
        self.name = txt_region.strip().rsplit(" ",1)[1]
        self.permissions = perm
        self.start = int(start, 16)
        self.end = int(end, 16)
        self.size = self.end - self.start
        self.f.seek(ptr or self.start)
        self.data = ''
    
    def seek(self, pos):
        self.f.seek(pos)
    
    def __del__(self):
        self.f.close()
        
    def __str__(self):
        return "<LinuxMemRegion size=%s start=%s end=%s permissions=%s name=%s"%(self.size,
                                                                         self.start,
                                                                         self.end,
                                                                         self.permissions,
                                                                         self.name)
    def contents(self):
        if self.data:
            return self.data
        self.f.seek(self.start)
        self.data = self.f.read(self.size)
        return bytearray(self.data)
    
    def finditer(self, s, start=None, end=None):
        index = -2
        data = self.contents()
        while index is not -1:
            index = data.find(s, start, end)
            if index is -1:
                break
            start = index+1
            yield index
        


if __name__=="__main__":  
    if not len(sys.argv)>1:
        print "usage: <pid>"
        sys.exit(1)
        
    pid = sys.argv[1]
    pmem = LinuxProcMemory(pid)
    
    for region in (r for r in pmem.regions if all(p in r.permissions for p in "rw") and not "deleted" in r.name):    #only check read/writable pages
        print region
        print region.txt_region
        print region.name
    
        index = 0
        data = region.contents()
        # struct scanning
        while index < region.size:
            struct_rsa, struct_dsa, struct_ssl_session,struct_dh,struct_ec_key,struct_asn1 = None,None,None,None,None,asn1sequence()
            if index%(1024*8)==0:
                print hex(index)
            try:
                struct_ssl_session = CStruct.class_from_template(ssl_session_st).from_buffer(data, index)
            except ValueError,ve:
                print "struct_ssl_session",repr(ve)
            #struct_ssl_session.from_bytes(data[index:index+len(struct_ssl_session)])
            #struct_bignum.from_bytes(data[index:index+len(struct_bignum)])
            try:
                struct_rsa = CStruct.class_from_template(rsa_st).from_buffer(data, index)
            except ValueError,ve:
                pass
                #print "struct_rsa",repr(ve)
            try:
                struct_dsa = CStruct.class_from_template(dsa_st).from_buffer(data, index)
            except ValueError,ve:
                pass
                #print "struct_dsa",repr(ve)
            try:
                struct_dh = CStruct.class_from_template(dh_st).from_buffer(data, index)
            except ValueError,ve:
                pass
                #print "struct_dh",repr(ve)
            try:
                struct_ec_key = CStruct.class_from_template(ec_key_st).from_buffer(data, index)
            except ValueError,ve:
                pass
                #print "struct_ec_key",repr(ve)
            
            #struct_rsa.from_bytes(data[index:index+len(struct_rsa)])
            #print struct_rsa.version
            #print repr(struct_rsa.to_bytes())
            if struct_rsa and struct_rsa.is_valid(mem=pmem):
                print struct_rsa
                raw_input("--> valid struct_rsa struct!")
            elif struct_dsa and struct_dsa.is_valid(mem=pmem):
                print struct_dsa
                raw_input("--> valid struct_dsa struct!")
                #if False and struct_bignum.is_valid(mem=pmem):
                #    print struct_bignum
                #    raw_input("--> valid struct_bignum struct!")
            elif struct_ssl_session and struct_ssl_session.is_valid(mem=pmem):
                print struct_ssl_session
                raw_input("--> valid struct_ssl_session struct!")
            elif struct_ec_key and struct_ec_key.is_valid(mem=pmem):
                print struct_ec_key
                raw_input("--> valid struct_ec_key struct!")
            elif struct_dh and struct_dh.is_valid(mem=pmem):
                print struct_dh
                raw_input("--> valid struct_dh struct!")
            elif data[index]=='\x30' and struct_asn1.consume(data[index:index+1024*1024*1024]): # seq. start
                print struct_asn1
                raw_input("--> valid asn1 sequence!")
                
            if not struct_rsa \
                and not struct_dsa \
                and not struct_ssl_session \
                and not struct_dh \
                and not struct_ec_key:
                print "wasnt able to check any struct for that region, skipping region."
                break
            index+=1