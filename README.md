# pymemscrape
A python-ctypes based process memory scraper that attempts to find key-material by matching template C structs in memory

This is just a python PoC. There is lots of space for improvement :)

# Templates

* OpenSSL ssl_session_st - SSL/TLS session struct containing the master_secret (decrypt communication for any cipherspec)
* OpenSSL rsa_st, dsa_st - RSA and DSA key material (OpenSSH)
* OpenSSL ec_key_st - Elliptic Curve key material
* OpenSSL bignum_st - bignum struct matching
* Generic ASN.1 - generic ASN.1 matching (Certificates, PubKey, PrivKey and other ASN.1 encoded objects)

# Example

Extract master_key, session_id from openssl s_client TLS1.0 session with ECDHE-RSA-AES256-SHA.

Start the server:

	#> openssl s_server &
	[1] 16462
	
initiate s_client connection for any ECDH cipher:

	#> # openssl s_client -connect localhost:4433 -tls1 -cipher ECDH
	CONNECTED(00000003)
	-----BEGIN SSL SESSION PARAMETERS-----
	MFoCAQECAgMBBALAFAQABDDy/bMXYX54SMKJf2VXblrBfnauG1U+C/giUOSlKYj6
	66moOC1548UkL9asG6ulcDqhBgIEVlYqAKIEAgIBLKQGBAQBAAAAqwMEAQE=
	-----END SSL SESSION PARAMETERS-----
	Shared ciphers:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-AES256-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:AECDH-AES128-SHA:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:AECDH-RC4-SHA:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:ECDHE-RSA-NULL-SHA:ECDHE-ECDSA-NULL-SHA:AECDH-NULL-SHA:ECDH-RSA-NULL-SHA:ECDH-ECDSA-NULL-SHA
	CIPHER is ECDHE-RSA-AES256-SHA
	Secure Renegotiation IS supported
	---
	Certificate chain
	 0 s:/C=AU/ST=QLD/O=Mincom Pty. Ltd./OU=CS/CN=SSLeay demo server
	   i:/C=AU/ST=QLD/CN=SSLeay/rsa test CA
	---
	Server certificate
	-----BEGIN CERTIFICATE-----
	MIIBgjCCASwCAQQwDQYJKoZIhvcNAQEEBQAwODELMAkGA1UEBhMCQVUxDDAKBgNV
	BAgTA1FMRDEbMBkGA1UEAxMSU1NMZWF5L3JzYSB0ZXN0IENBMB4XDTk1MTAwOTIz
	MzIwNVoXDTk4MDcwNTIzMzIwNVowYDELMAkGA1UEBhMCQVUxDDAKBgNVBAgTA1FM
	RDEZMBcGA1UEChMQTWluY29tIFB0eS4gTHRkLjELMAkGA1UECxMCQ1MxGzAZBgNV
	BAMTElNTTGVheSBkZW1vIHNlcnZlcjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC3
	LCXcScWua0PFLkHBLm2VejqpA1F4RQ8q0VjRiPafjx/Z/aWH3ipdMVvuJGa/wFXb
	/nDFLDlfWp+oCPwhBtVPAgMBAAEwDQYJKoZIhvcNAQEEBQADQQArNFsihWIjBzb0
	DCsU0BvL2bvSwJrPEqFlkDq3F4M6EGutL9axEcANWgbbEdAvNJD1dmEmoWny27Pn
	IMs6ZOZB
	-----END CERTIFICATE-----
	subject=/C=AU/ST=QLD/O=Mincom Pty. Ltd./OU=CS/CN=SSLeay demo server
	issuer=/C=AU/ST=QLD/CN=SSLeay/rsa test CA
	---
	No client certificate CA names sent
	---
	SSL handshake has read 863 bytes and written 310 bytes
	---
	New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-SHA
	Server public key is 512 bit
	Secure Renegotiation IS supported
	Compression: zlib compression
	Expansion: zlib compression
	SSL-Session:
	    Protocol  : TLSv1
	    Cipher    : ECDHE-RSA-AES256-SHA
	    Session-ID: 4D7A7A527FB54F82B4D1687368DE234EDEB8F71A8EF33B64E6FBB58E4F751BC9
	    Session-ID-ctx:
	    Master-Key: F2FDB317617E7848C2897F65576E5AC17E76AE1B553E0BF82250E4A52988FAEBA9A8382D79E3C5242FD6AC1BABA5703A
	    Key-Arg   : None
	    PSK identity: None
	    PSK identity hint: None
	    SRP username: None
	    TLS session ticket lifetime hint: 300 (seconds)
	    TLS session ticket:
	    0000 - 8c 52 eb 9a da c6 78 ee-4e 1f 4f 3e 48 0f 32 0e   .R....x.N.O>H.2.
	    0010 - c2 f0 f3 1a a7 5b 6b f6-e4 f2 64 b5 33 c9 5d 31   .....[k...d.3.]1
	    0020 - 53 5b 00 f8 ef 92 9a 84-c8 65 43 48 9b 83 f8 29   S[.......eCH...)
	    0030 - 84 37 8e 36 67 b8 32 13-b3 f7 15 62 fa 81 b2 61   .7.6g.2....b...a
	    0040 - 31 6b 3f ba 6d 46 ba a7-7b 82 a3 e2 63 71 b4 ae   1k?.mF..{...cq..
	    0050 - ef 9b fd 8c cc 08 00 8f-1c e6 df 08 39 26 91 6c   ............9&.l
	    0060 - 9d 03 aa 9f 6e 8f d7 da-03 34 04 d3 e6 ea 3d 3c   ....n....4....=<
	    0070 - ab e8 c1 62 86 af 1f 8d-ee e1 48 2d 69 ac d2 b1   ...b......H-i...
	    0080 - 17 dd ab 1a 72 8f 42 7d-54 25 5a 1c c4 dd b2 88   ....r.B}T%Z.....
	    0090 - 24 17 8c ae 86 47 bc 6e-f6 63 47 d8 9c 42 9e 3c   $....G.n.cG..B.<
	
	    Compression: 1 (zlib compression)
	    Start Time: 1448487424
	    Timeout   : 7200 (sec)
	    Verify return code: 21 (unable to verify the first certificate)
	---
	
scrape the memory for the ssl session struct:

	#> for p in $(pgrep openssl); do python memscrape.py $p; done 
	<LinuxMemRegion size=880640 start=164278272 end=165158912 permissions=rw-p name=[heap]
	09cab000-09d82000 rw-p 00000000 00:00 0          [heap]
	[heap]
	0x0
	0x2000
	0x4000
	0x6000
	0x8000
	0xa000
	0xc000
	0xe000
	0x10000
	0x12000
	0x14000
	0x16000
	0x18000
	0x1a000
	0x1c000
	0x1e000
	0x20000
	0x22000
	0x24000
	0x26000
	0x28000
	struct ssl_session_st {
	    long            version = 769
	    ulong           key_arg_length = 0L
	    char_Array_8    key_arg = ''
	    long            master_key_length = 48
	    char_Array_48   master_key = '\xf2\xfd\xb3\x17a~xH\xc2\x89\x7feWnZ\xc1~v\xae\x1bU>\x0b\xf8"P\xe4\xa5)\x88\xfa\xeb\xa9\xa88-y\xe3\xc5$/\xd6\xac\x1b\xab\xa5p:'
	    long            session_id_length = 32
	    char_Array_32   session_id = 'MzzR\x7f\xb5O\x82\xb4\xd1hsh\xde#N\xde\xb8\xf7\x1a\x8e\xf3;d\xe6\xfb\xb5\x8eOu\x1b\xc9'
	    long            sid_ctx_length = 0
	    char_Array_32   sid_ctx = ''
	    long            not_resumable = 0
	    void*           sess_cert = None
	    void*           peer = None
	    long            verify_result = 164453248
	    long            references = 164450800
	    long            timeout = 21
	    long            time = 1
	    long            compress_meth = 7200
	    void*           cipher = '0x56562a00'
	    ulong           cipher_id = 1L
	    void*           ciphers = '0xb7758ba0L'
	}
	--> valid struct_ssl_session struct!

master_key matches output of s_client, version matches 0x0301==769==TLS_1_0.
		
