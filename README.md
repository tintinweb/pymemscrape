# pymemscrape
A python-ctypes based process memory scraper that attempts to find key-material by matching template C structs in memory

This is just a python PoC. There is lots of space for improvement :)

# Templates

* OpenSSL ssl_session_st - SSL/TLS session struct containing the master_secret (decrypt communication for any cipherspec)
* OpenSSL rsa_st, dsa_st - RSA and DSA key material (OpenSSH)
* OpenSSL ec_key_st - Elliptic Curve key material
* OpenSSL bignum_st - bignum struct matching
* Generic ASN.1 - generic ASN.1 matching (Certificates, PubKey, PrivKey and other ASN.1 encoded objects)


