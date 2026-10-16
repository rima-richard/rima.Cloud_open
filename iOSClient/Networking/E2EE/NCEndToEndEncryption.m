// SPDX-FileCopyrightText: Nextcloud GmbH
// SPDX-FileCopyrightText: 2017 Marino Faggiana
// SPDX-License-Identifier: GPL-3.0-or-later


#import "NCEndToEndEncryption.h"
#import "NCBridgeSwift.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <OpenSSL/OpenSSL.h>
#import <openssl/provider.h>
#import <openssl/evp.h>
#import <openssl/err.h>
#import <limits.h>
#import <sys/stat.h>
#import <unistd.h>

#define addName(field, value) X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, (unsigned char *)value, -1, -1, 0);

#define IV_DELIMITER_ENCODED_OLD    @"fA=="
#define IV_DELIMITER_ENCODED        @"|"
#define PBKDF2_KEY_LENGTH           256
//#define PBKDF2_SALT                 @"$4$YmBjm3hk$Qb74D5IUYwghUmzsMqeNFx5z0/8$"

#define ASYMMETRIC_STRING_TEST      @"Nextcloud a safe home for all your data"

#define fileNameCertificate         @"cert.pem"
#define fileNameCSR                 @"csr.pem"
#define fileNamePrivateKey          @"privateKey.pem"
#define fileNamePubliceKey          @"publicKey.pem"

#define streamBuffer                1024

#define AES_KEY_128_LENGTH          16
#define AES_KEY_256_LENGTH          32
#define AES_IVEC_LENGTH             12
#define AES_GCM_TAG_LENGTH          16
#define AES_SALT_LENGTH             40
#define AES_TAG_LENGTH              16

// Older E2EE clients used 16-byte nonces; current clients generate 12 bytes.
static BOOL NCValidGCMParameters(NSData *key, int keyLen, NSData *iv, NSData *tag) {
    return (keyLen == AES_KEY_128_LENGTH || keyLen == AES_KEY_256_LENGTH) &&
        key.length == (NSUInteger)keyLen &&
        (iv.length == AES_IVEC_LENGTH || iv.length == 16) &&
        tag.length == AES_GCM_TAG_LENGTH;
}

@interface NCEndToEndEncryption ()
{
    NSData *_privateKeyData;
    NSData *_publicKeyData;
    NSData *_csrData;
}
@end

@implementation NCEndToEndEncryption

+ (instancetype)shared {
    static dispatch_once_t once;
    static NCEndToEndEncryption *shared;
    dispatch_once(&once, ^{
        // Load OpenSSL legacy provider once
        nk_openssl_load_legacy_provider_if_needed();
        shared = [self new];
    });
    return shared;
}

void nk_openssl_load_legacy_provider_if_needed(void) {
    OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
    if (!deflt) {
        ERR_print_errors_fp(stderr);
    }

    OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        ERR_print_errors_fp(stderr);
    }
}

#
#pragma mark - Generate Certificate X509 - CSR - Private Key
#

- (BOOL)generateCertificateX509WithUserId:(NSString *)userId directory:(NSString *)directory
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        return FALSE;
    }

    // Generate an new RSA KEY
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return FALSE;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return FALSE;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return FALSE;
    }

    X509 *x509 = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    long notBefore = [[NSDate date] timeIntervalSinceDate:[NSDate date]];
    long notAfter = [[[NSDate date] dateByAddingTimeInterval:60*60*24*365*10] timeIntervalSinceDate:[NSDate date]]; // 10 year
    X509_gmtime_adj(X509_get_notBefore(x509), notBefore);
    X509_gmtime_adj(X509_get_notAfter(x509), notAfter);
    
    X509_set_pubkey(x509, pkey);
    
    X509_NAME * name;
    name = X509_get_subject_name(x509);
    
    // Now to add the subject name fields to the certificate
    // I use a macro here to make it cleaner.
    
    const unsigned char *cUserId = (const unsigned char *) [userId cStringUsingEncoding:NSUTF8StringEncoding];

    // Common Name = UserID.
    addName("CN", cUserId);

    // The organization of the cert.
    addName("O",  "Nextcloud");
    
    // The city of the organization.
    addName("L",  "Stuttgart");
    
    // The state/province of the organization.
    addName("ST",  "Baden-Wuerttemberg");

    // The country (ISO 3166) of the organization
    addName("C",  "DE");
    
    X509_set_issuer_name(x509, name);
    
    /*
     for (SANObject * san in self.options.sans) {
     if (!san.value || san.value.length <= 0) {
     continue;
     }
     
     NSString * prefix = san.type == SANObjectTypeIP ? @"IP:" : @"DNS:";
     NSString * value = [NSString stringWithFormat:@"%@%@", prefix, san.value];
     NSLog(@"Add subjectAltName %@", value);
     
     X509_EXTENSION * extension = NULL;
     ASN1_STRING * asnValue = ASN1_STRING_new();
     ASN1_STRING_set(asnValue, (const unsigned char *)[value UTF8String], (int)value.length);
     X509_EXTENSION_create_by_NID(&extension, NID_subject_alt_name, 0, asnValue);
     X509_add_ext(x509, extension, -1);
     }
     */
    
    // Specify the encryption algorithm of the signature.
    // SHA256 should suit your needs.
    if (X509_sign(x509, pkey, EVP_sha256()) < 0) {
        return NO;
    }
    
    // Extract CSR, publicKey, privateKey
    int len;
    char *keyBytes;
    
    // CSR
    BIO *csrBIO = BIO_new(BIO_s_mem());
    X509_REQ *certReq = X509_to_X509_REQ(x509, pkey, EVP_sha256());
    PEM_write_bio_X509_REQ(csrBIO, certReq);
    
    len = BIO_pending(csrBIO);
    keyBytes  = malloc(len);
    
    BIO_read(csrBIO, keyBytes, len);
    _csrData = [NSData dataWithBytes:keyBytes length:len];

    // PublicKey
    BIO *publicKeyBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicKeyBIO, pkey);
    
    len = BIO_pending(publicKeyBIO);
    keyBytes  = malloc(len);
    
    BIO_read(publicKeyBIO, keyBytes, len);
    _publicKeyData = [NSData dataWithBytes:keyBytes length:len];
    self.generatedPublicKey = [[NSString alloc] initWithData:_publicKeyData encoding:NSUTF8StringEncoding];

    // PrivateKey
    BIO *privateKeyBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS8PrivateKey(privateKeyBIO, pkey, NULL, NULL, 0, NULL, NULL);
    
    len = BIO_pending(privateKeyBIO);
    keyBytes = malloc(len);
    
    BIO_read(privateKeyBIO, keyBytes, len);
    _privateKeyData = [NSData dataWithBytes:keyBytes length:len];
    self.generatedPrivateKey = [[NSString alloc] initWithData:_privateKeyData encoding:NSUTF8StringEncoding];

    if(keyBytes)
        free(keyBytes);
    
#ifdef DEBUG
    // Save to disk [DEBUG MODE]
    [self saveToDiskPEMWithCert:x509 key:pkey directory:directory];
#endif
    
    return YES;
}

- (NSString *)extractPublicKeyFromCertificate:(NSString *)pemCertificate
{
    NSData *pem = [pemCertificate dataUsingEncoding:NSUTF8StringEncoding];
    if (!pem.length || pem.length > INT_MAX) return nil;
    BIO *certBio = BIO_new_mem_buf(pem.bytes, (int)pem.length);
    if (!certBio) return nil;
    X509 *certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
    if (!certX509) {
        BIO_free(certBio);
        return nil;
    }
    EVP_PKEY *pkey = X509_get_pubkey(certX509);
    NSString *publicKey = pkey ? [self pubKeyToString:pkey] : nil;
    
    EVP_PKEY_free(pkey);
    BIO_free(certBio);
    X509_free(certX509);
    
    return publicKey;
}

- (NSString *)extractPublicKeyFromCertificateSigningRequest:(NSString *)pemCSR
{
    const char *ptrCSR = [pemCSR cStringUsingEncoding:NSUTF8StringEncoding];

    BIO *csrBio = BIO_new_mem_buf(
        ptrCSR,
        (int)strlen(ptrCSR)
    );

    if (!csrBio) {
        return nil;
    }

    X509_REQ *csr = PEM_read_bio_X509_REQ(
        csrBio,
        NULL,
        NULL,
        NULL
    );

    if (!csr) {
        fprintf(stderr, "unable to parse CSR in memory\n");
        BIO_free(csrBio);
        return nil;
    }

    EVP_PKEY *pkey = X509_REQ_get_pubkey(csr);

    if (!pkey) {
        X509_REQ_free(csr);
        BIO_free(csrBio);
        return nil;
    }

    NSString *publicKey = [self pubKeyToString:pkey];

    EVP_PKEY_free(pkey);
    X509_REQ_free(csr);
    BIO_free(csrBio);

    return publicKey;
}

- (BOOL)saveToDiskPEMWithCert:(X509 *)x509 key:(EVP_PKEY *)pkey directory:(NSString *)directory
{
    FILE *f;
    
    // Certificate
    NSString *certificatePath = [NSString stringWithFormat:@"%@/%@", directory, fileNameCertificate];
    f = fopen([certificatePath fileSystemRepresentation], "wb");
    if (PEM_write_X509(f, x509) < 0) {
        // Error writing to disk.
        fclose(f);
        return NO;
    }
    fclose(f);
    
    // PublicKey
    NSString *publicKeyPath = [NSString stringWithFormat:@"%@/%@", directory, fileNamePubliceKey];
    f = fopen([publicKeyPath fileSystemRepresentation], "wb");
    if (PEM_write_PUBKEY(f, pkey) < 0) {
        // Error
        fclose(f);
        return NO;
    }
    fclose(f);
    
    // Here you write the private key (pkey) to disk. OpenSSL will encrypt the
    // file using the password and cipher you provide.
    //if (PEM_write_PrivateKey(f, pkey, EVP_des_ede3_cbc(), (unsigned char *)[password UTF8String], (int)password.length, NULL, NULL) < 0) {
    
    // PrivateKey
    NSString *privatekeyPath = [NSString stringWithFormat:@"%@/%@", directory, fileNamePrivateKey];
    f = fopen([privatekeyPath fileSystemRepresentation], "wb");
    if (PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL) < 0) {
        // Error
        fclose(f);
        return NO;
    }
    fclose(f);
    
    // CSR Request sha256
    NSString *csrPath = [NSString stringWithFormat:@"%@/%@", directory, fileNameCSR];
    f = fopen([csrPath fileSystemRepresentation], "wb");
    X509_REQ *certreq = X509_to_X509_REQ(x509, pkey, EVP_sha256());
    if (PEM_write_X509_REQ(f, certreq) < 0) {
        // Error
        fclose(f);
        return NO;
    }
    fclose(f);
    
    return YES;
}

- (BOOL)saveP12WithCert:(X509 *)x509 key:(EVP_PKEY *)pkey directory:(NSString *)directory finished:(void (^)(NSError *))finished
{
    //PKCS12 * p12 = PKCS12_create([password UTF8String], NULL, pkey, x509, NULL, 0, 0, PKCS12_DEFAULT_ITER, 1, NID_key_usage);
    PKCS12 *p12 = PKCS12_create(NULL, NULL, pkey, x509, NULL, 0, 0, PKCS12_DEFAULT_ITER, 1, NID_key_usage);
    
    NSString *path = [NSString stringWithFormat:@"%@/certificate.p12", directory];
    
    FILE *f = fopen([path fileSystemRepresentation], "wb");
    
    if (i2d_PKCS12_fp(f, p12) != 1) {
        fclose(f);
        return NO;
    }
    fclose(f);
    
    return YES;
}

#
#pragma mark - Verify X.509 certificate
#

//  This method verifies that the provided X.509 certificate (issued by the server)
//  was actually signed using the server's own public key.
- (BOOL)verifyCertificate:(NSString *)certificate PublicKey:(NSString *)publicKey
{
    BOOL success = NO;
    BIO *certBio = NULL;
    BIO *pubBio = NULL;
    X509 *cert = NULL;
    EVP_PKEY *serverPubKey = NULL;

    // Convert NSStrings to UTF-8 data buffers
    NSData *certData = [certificate dataUsingEncoding:NSUTF8StringEncoding];
    NSData *pubData  = [publicKey dataUsingEncoding:NSUTF8StringEncoding];
    if (certData.length == 0 || pubData.length == 0) {
        return NO;
    }

    // Create BIOs from memory buffers
    certBio = BIO_new_mem_buf((void *)certData.bytes, (int)certData.length);
    pubBio  = BIO_new_mem_buf((void *)pubData.bytes, (int)pubData.length);
    if (!certBio || !pubBio) {
        goto cleanup;
    }

    // Read X.509 certificate from PEM text
    cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
    if (!cert) {
        goto cleanup;
    }

    // Read public key from PEM text
    serverPubKey = PEM_read_bio_PUBKEY(pubBio, NULL, NULL, NULL);
    if (!serverPubKey) {
        goto cleanup;
    }

    // Verify that the certificate was signed using this public key
    int verifyResult = X509_verify(cert, serverPubKey);
    success = (verifyResult == 1);

cleanup:
    if (serverPubKey) EVP_PKEY_free(serverPubKey);
    if (cert) X509_free(cert);
    if (certBio) BIO_free(certBio);
    if (pubBio) BIO_free(pubBio);

    return success;
}

#
#pragma mark - Create CSR & Encrypt/Decrypt Private Key
#

- (NSString *)createCSR:(NSString *)userId directory:(NSString *)directory
{
    // Create Certificate, if do not exists
    if (!_csrData) {
        if (![self generateCertificateX509WithUserId:userId directory:directory])
            return nil;
    }
    
    NSString *csr = [[NSString alloc] initWithData:_csrData encoding:NSUTF8StringEncoding];
    
    return csr;
}

- (NSString *)encryptPrivateKey:(NSString *)userId directory:(NSString *)directory passphrase:(NSString *)passphrase privateKey:(NSString **)privateKey
{
    NSMutableData *cipher = [NSMutableData new];

    if (!_privateKeyData) {
        if (![self generateCertificateX509WithUserId:userId directory:directory])
            return nil;
    }

    NSMutableData *key = [NSMutableData dataWithLength:PBKDF2_KEY_LENGTH / 8];
    NSData *salt = [self generateSalt:AES_SALT_LENGTH];

    // Clean passphrase
    passphrase = [passphrase stringByReplacingOccurrencesOfString:@" " withString:@""];

    // PBKDF2-HMAC-SHA256
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         passphrase.UTF8String,
                         (int)passphrase.length,
                         salt.bytes,
                         (int)salt.length,
                         kCCPRFHmacAlgSHA256,
                         600000,
                         key.mutableBytes,
                         key.length);

    NSData *initializationVector = [self generateIV:AES_IVEC_LENGTH];
    NSMutableData *authenticationTag = [NSMutableData dataWithLength:AES_TAG_LENGTH];

    // Base64 encode private key
    NSString *pkEncoded = [_privateKeyData base64EncodedStringWithOptions:0];
    NSData *pkEncodedData = [pkEncoded dataUsingEncoding:NSUTF8StringEncoding];

    BOOL result = [self encryptData:pkEncodedData
                             cipher:&cipher
                                key:key
                            keyLen:AES_KEY_256_LENGTH
              initializationVector:initializationVector
                 authenticationTag:&authenticationTag];

    if (result && cipher) {
        NSString *cipherString = [cipher base64EncodedStringWithOptions:0];
        NSString *ivString = [initializationVector base64EncodedStringWithOptions:0];
        NSString *saltString = [salt base64EncodedStringWithOptions:0];

        NSString *encryptPrivateKey = [NSString stringWithFormat:@"%@%@%@%@%@",
                                       cipherString, IV_DELIMITER_ENCODED,
                                       ivString, IV_DELIMITER_ENCODED,
                                       saltString];

        // Output: decoded private key (for UI, debug, etc.)
        NSString *decodedPrivateKey = [[NSString alloc] initWithData:_privateKeyData encoding:NSUTF8StringEncoding];
        if (!decodedPrivateKey) {
            decodedPrivateKey = [_privateKeyData base64EncodedStringWithOptions:0];
        }
        *privateKey = decodedPrivateKey;

        return encryptPrivateKey;
    }

    return nil;
}

- (NSData *)decryptPrivateKey:(NSString *)privateKey passphrase:(NSString *)passphrase
{
    if (!privateKey || !passphrase) return nil;
    NSMutableData *plain = [NSMutableData new];
    NSMutableData *key = [NSMutableData dataWithLength:PBKDF2_KEY_LENGTH / 8];

    // Split the encrypted private key format: base64(cipher+tag) + IV + salt
    NSArray *cipherArray = [privateKey componentsSeparatedByString:IV_DELIMITER_ENCODED];
    if (cipherArray.count != 3) {
        cipherArray = [privateKey componentsSeparatedByString:IV_DELIMITER_ENCODED_OLD];
        if (cipherArray.count != 3) {
            NSLog(@"Invalid encrypted key format: expected 3 parts");
            return nil;
        }
    }

    NSString *cipherBase64 = cipherArray[0];
    NSData *fullCipher = [[NSData alloc] initWithBase64EncodedString:cipherBase64 options:0];
    if (!fullCipher || fullCipher.length < 16) {
        NSLog(@"Failed to decode cipher or too short");
        return nil;
    }

    NSData *cipher = [fullCipher subdataWithRange:NSMakeRange(0, fullCipher.length - 16)];
    NSData *authenticationTag = [fullCipher subdataWithRange:NSMakeRange(fullCipher.length - 16, 16)];

    NSData *initializationVector = [[NSData alloc] initWithBase64EncodedString:cipherArray[1] options:0];
    NSData *salt = [[NSData alloc] initWithBase64EncodedString:cipherArray[2] options:0];

    if (!NCValidGCMParameters(key, AES_KEY_256_LENGTH, initializationVector, authenticationTag) || !salt.length || salt.length > INT_MAX) {
        NSLog(@"One or more components (cipher, tag, IV, salt) are missing");
        return nil;
    }

    // Clean passphrase from spaces
    passphrase = [passphrase stringByReplacingOccurrencesOfString:@" " withString:@""];

    // Derive AES key using PBKDF2
    int derivation = CCKeyDerivationPBKDF(kCCPBKDF2,
                                          passphrase.UTF8String,
                                          (int)passphrase.length,
                                          salt.bytes,
                                          (int)salt.length,
                                          kCCPRFHmacAlgSHA256,
                                          600000,
                                          key.mutableBytes,
                                          key.length);

    if (derivation != kCCSuccess) {
        NSLog(@"PBKDF2 key derivation failed: %d", derivation);
        return nil;
    }

    // AES-GCM decryption
    BOOL success = [self decryptData:cipher plain:&plain key:key keyLen:AES_KEY_256_LENGTH initializationVector:initializationVector authenticationTag:authenticationTag];

    if (!success) {
        // Try OLD format (PBKDF2-HMAC-SHA1 + 1024)
        derivation = CCKeyDerivationPBKDF(kCCPBKDF2,
                                          passphrase.UTF8String,
                                          (int)passphrase.length,
                                          salt.bytes,
                                          (int)salt.length,
                                          kCCPRFHmacAlgSHA1,
                                          1024,
                                          key.mutableBytes,
                                          key.length);
        if (derivation == kCCSuccess) {
            success = [self decryptData:cipher plain:&plain key:key keyLen:AES_KEY_256_LENGTH initializationVector:initializationVector authenticationTag:authenticationTag];
        }
    }

    if (!success) {
        NSLog(@"❌ Failed to decrypt with both PBKDF2 formats.");
        return nil;
    }

    return plain;
}

#
#pragma mark - Encrypt / Decrypt file material
#

- (NSString *)encryptPayloadFile:(NSData *)encrypted key:(NSString *)key
{
    NSMutableData *cipher;
    NSData *authenticationTag = [NSData new];

    // Key
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];

    // Initialization Vector
    NSData *initializationVector = [self generateIV:AES_IVEC_LENGTH];

    BOOL result = [self encryptData:encrypted cipher:&cipher key:keyData keyLen:AES_KEY_128_LENGTH initializationVector:initializationVector authenticationTag:&authenticationTag];

    if (cipher != nil && result) {

        NSString *cipherString = [cipher base64EncodedStringWithOptions:0];
        NSString *initializationVectorString = [initializationVector base64EncodedStringWithOptions:0];
        NSString *payload = [NSString stringWithFormat:@"%@%@%@", cipherString, IV_DELIMITER_ENCODED, initializationVectorString];

        return payload;
    }

    return nil;
}


- (NSString *)encryptPayloadFile:(NSData *)encrypted key:(NSString *)key initializationVector:(NSString **)initializationVector authenticationTag:(NSString **)authenticationTag
{
    NSMutableData *cipher;
    NSData *authenticationTagData = [NSData new];

    // Key
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];

    // Initialization Vector
    NSData *initializationVectorData = [self generateIV:AES_IVEC_LENGTH];

    BOOL result = [self encryptData:encrypted cipher:&cipher key:keyData keyLen:AES_KEY_128_LENGTH initializationVector:initializationVectorData authenticationTag:&authenticationTagData];

    if (cipher != nil && result) {

        *initializationVector = [initializationVectorData base64EncodedStringWithOptions:0];
        *authenticationTag = [authenticationTagData base64EncodedStringWithOptions:0];
        NSString *payload = [cipher base64EncodedStringWithOptions:0];
        
        return payload;
    }

    return nil;
}


- (NSData *)decryptPayloadFile:(NSString *)encrypted key:(NSString *)key
{
    if (!encrypted || !key) return nil;
    NSRange range = [encrypted rangeOfString:IV_DELIMITER_ENCODED];
    if (range.location == NSNotFound) {
        range = [encrypted rangeOfString:IV_DELIMITER_ENCODED_OLD];
        if (range.location == NSNotFound) return nil;
    }

    NSData *fullCipher = [[NSData alloc] initWithBase64EncodedString:[encrypted substringToIndex:range.location] options:0];
    if (fullCipher.length < AES_GCM_TAG_LENGTH) return nil;
    NSData *cipher = [fullCipher subdataWithRange:NSMakeRange(0, fullCipher.length - AES_GCM_TAG_LENGTH)];
    NSData *tag = [fullCipher subdataWithRange:NSMakeRange(fullCipher.length - AES_GCM_TAG_LENGTH, AES_GCM_TAG_LENGTH)];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    NSData *iv = [[NSData alloc] initWithBase64EncodedString:[encrypted substringFromIndex:NSMaxRange(range)] options:0];
    NSMutableData *plain = nil;
    return [self decryptData:cipher plain:&plain key:keyData keyLen:AES_KEY_128_LENGTH initializationVector:iv authenticationTag:tag] ? plain : nil;
}

- (NSData *)decryptPayloadFile:(NSString *)encrypted key:(NSString *)key initializationVector:(NSString *)initializationVector authenticationTag:(NSString *)authenticationTag
{
    if (!encrypted || !key || !initializationVector || !authenticationTag) return nil;
    // Android may append exactly one nonce suffix to the base64 payload.
    NSString *suffix = [IV_DELIMITER_ENCODED stringByAppendingString:initializationVector];
    if ([encrypted hasSuffix:suffix]) {
        encrypted = [encrypted substringToIndex:encrypted.length - suffix.length];
    }
    NSData *fullCipher = [[NSData alloc] initWithBase64EncodedString:encrypted options:0];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    NSData *iv = [[NSData alloc] initWithBase64EncodedString:initializationVector options:0];
    NSData *tag = [[NSData alloc] initWithBase64EncodedString:authenticationTag options:0];
    if (fullCipher.length < AES_GCM_TAG_LENGTH || !NCValidGCMParameters(keyData, AES_KEY_128_LENGTH, iv, tag)) return nil;

    // The payload carries the tag as well as the separate metadata field.
    NSData *appendedTag = [fullCipher subdataWithRange:NSMakeRange(fullCipher.length - AES_GCM_TAG_LENGTH, AES_GCM_TAG_LENGTH)];
    if (![appendedTag isEqualToData:tag]) return nil;
    NSData *cipher = [fullCipher subdataWithRange:NSMakeRange(0, fullCipher.length - AES_GCM_TAG_LENGTH)];
    NSMutableData *plain = nil;
    return [self decryptData:cipher plain:&plain key:keyData keyLen:AES_KEY_128_LENGTH initializationVector:iv authenticationTag:tag] ? plain : nil;
}

#
#pragma mark - Encrypt / Decrypt file
#

- (BOOL)encryptFile:(NSString *)fileName fileNameIdentifier:(NSString *)fileNameIdentifier directory:(NSString *)directory key:(NSString **)key initializationVector:(NSString **)initializationVector authenticationTag:(NSString **)authenticationTag
{
    NSData *authenticationTagData;
    NSData *keyData = [self generateKey:AES_KEY_128_LENGTH];
    NSData *initializationVectorData = [self generateIV:AES_IVEC_LENGTH];

    BOOL result = [self encryptFile:[NSString stringWithFormat:@"%@/%@", directory, fileName] fileNameCipher:[NSString stringWithFormat:@"%@/%@", directory, fileNameIdentifier] key:keyData keyLen:AES_KEY_128_LENGTH initializationVector:initializationVectorData authenticationTag:&authenticationTagData];

    if (result) {

        *key = [keyData base64EncodedStringWithOptions:0];
        *initializationVector = [initializationVectorData base64EncodedStringWithOptions:0];
        *authenticationTag = [authenticationTagData base64EncodedStringWithOptions:0];

        if (key == nil || initializationVector == nil || authenticationTag == nil) {
            return false;
        } else {
            return true;
        }
    }
    
    return false;
}

- (BOOL)decryptFile:(NSString *)fileName fileNameView:(NSString *)fileNameView ocId:(NSString *)ocId userId:(NSString *)userId urlBase:(NSString *)urlBase key:(NSString *)key initializationVector:(NSString *)initializationVector authenticationTag:(NSString *)authenticationTag
{
    if (!key || !initializationVector || !authenticationTag) return NO;
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
    NSData *initializationVectorData = [[NSData alloc] initWithBase64EncodedString:initializationVector options:0];
    NSData *authenticationTagData = [[NSData alloc] initWithBase64EncodedString:authenticationTag options:0];

    NSString *inputPath = [[[NCUtilityFileSystem alloc] init] getDirectoryProviderStorageOcId:ocId fileName:fileName userId:userId urlBase:urlBase];
    // Resolving the output must not create a visible placeholder before authentication.
    NSString *outputPath = [[inputPath stringByDeletingLastPathComponent] stringByAppendingPathComponent:fileNameView];
    return [self decryptFile:inputPath fileNamePlain:outputPath key:keyData keyLen:AES_KEY_128_LENGTH initializationVector:initializationVectorData authenticationTag:authenticationTagData];
}

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------------------------------------

#
#pragma mark - OPENSSL ENCRYPT/DECRYPT
#


#
#pragma mark - Encrypt/Decrypt asymmetric
#

- (NSData *)encryptAsymmetricData:(NSData *)plainData certificate:(NSString *)certificate
{
    EVP_PKEY *key = NULL;
    int status = 0;
    unsigned char *pKey = (unsigned char *)[certificate UTF8String];

    // Extract real publicKey
    BIO *bio = BIO_new_mem_buf(pKey, -1);
    if (!bio)
        return nil;

    X509 *x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
    if (!x509)
        return nil;

    key = X509_get_pubkey(x509);
    if (!key)
        return nil;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
        return nil;

    status = EVP_PKEY_encrypt_init(ctx);
    if (status <= 0)
        return nil;

    status = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (status <= 0)
        return nil;

    status = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    if (status <= 0)
        return nil;

    status = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    if (status <= 0)
        return nil;

    unsigned long outLen = 0;
    status = EVP_PKEY_encrypt(ctx, NULL, &outLen, [plainData bytes], (int)[plainData length]);
    if (status <= 0 || outLen == 0)
        return nil;

    unsigned char *out = (unsigned char *) malloc(outLen);
    status = EVP_PKEY_encrypt(ctx, out, &outLen, [plainData bytes], (int)[plainData length]);
    if (status <= 0)
        return nil;

    NSData *outData = [[NSData alloc] initWithBytes:out length:outLen];

    if (out)
        free(out);

    return outData;
}

- (NSData *)encryptAsymmetricData:(NSData *)plainData privateKey:(NSString *)privateKey
{
    EVP_PKEY *key = NULL;
    int status = 0;
    unsigned char *pKey = (unsigned char *)[privateKey UTF8String];

    BIO *bio = BIO_new_mem_buf(pKey, -1);
    if (!bio)
        return nil;

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!key)
        return nil;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
        return nil;

    status = EVP_PKEY_encrypt_init(ctx);
    if (status <= 0)
        return nil;

    status = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (status <= 0)
        return nil;

    status = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    if (status <= 0)
        return nil;

    status = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    if (status <= 0)
        return nil;

    unsigned long outLen = 0;
    status = EVP_PKEY_encrypt(ctx, NULL, &outLen, [plainData bytes], (int)[plainData length]);
    if (status <= 0 || outLen == 0)
        return nil;

    unsigned char *out = (unsigned char *) malloc(outLen);
    status = EVP_PKEY_encrypt(ctx, out, &outLen, [plainData bytes], (int)[plainData length]);
    if (status <= 0)
        return nil;

    NSData *outData = [[NSData alloc] initWithBytes:out length:outLen];

    if (out)
        free(out);

    return outData;
}

- (NSData *)decryptAsymmetricData:(NSData *)cipherData privateKey:(NSString *)privateKey
{
    unsigned char *pKey = (unsigned char *)[privateKey UTF8String];
    int status = 0;
    
    BIO *bio = BIO_new_mem_buf(pKey, -1);
    if (!bio)
        return nil;
    
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!key) {
        ERR_print_errors_fp(stderr);
        return nil;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
        return nil;
    
    status = EVP_PKEY_decrypt_init(ctx);
    if (status <= 0)
        return nil;
    
    status = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    if (status <= 0)
        return nil;
    
    status = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    if (status <= 0)
        return nil;
    
    status = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());
    if (status <= 0)
        return nil;
    
    unsigned long outLen = 0;
    status = EVP_PKEY_decrypt(ctx, NULL, &outLen, [cipherData bytes], (int)[cipherData length]);
    if (status <= 0 || outLen == 0)
        return nil;
    
    unsigned char *out = (unsigned char *) malloc(outLen);
    status = EVP_PKEY_decrypt(ctx, out, &outLen, [cipherData bytes], (int)[cipherData length]);
    if (status <= 0)
        return nil;

    NSData *outData = [[NSData alloc] initWithBytes:out length:outLen];

    if (out)
        free(out);
    
    return outData;
}

#
#pragma mark - AES/GCM/NoPadding
#

// Encryption data using GCM mode
- (BOOL)encryptData:(NSData *)plain cipher:(NSMutableData **)cipher key:(NSData *)key keyLen:(int)keyLen initializationVector:(NSData *)initializationVector authenticationTag:(NSData **)authenticationTag
{
    if (!cipher || !authenticationTag) return NO;
    *cipher = nil;
    *authenticationTag = nil;
    unsigned char tag[AES_GCM_TAG_LENGTH] = {0};
    if (!plain || plain.length > INT_MAX ||
        !NCValidGCMParameters(key, keyLen, initializationVector, [NSData dataWithBytes:tag length:sizeof(tag)])) return NO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NO;
    NSMutableData *output = [NSMutableData dataWithLength:plain.length + EVP_MAX_BLOCK_LENGTH];
    BOOL success = NO;
    int length = 0;
    int finalLength = 0;
    do {
        const EVP_CIPHER *algorithm = keyLen == AES_KEY_128_LENGTH ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
        if (EVP_EncryptInit_ex(ctx, algorithm, NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)initializationVector.length, NULL) != 1) break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key.bytes, initializationVector.bytes) != 1) break;
        if (EVP_EncryptUpdate(ctx, output.mutableBytes, &length, plain.bytes, (int)plain.length) != 1) break;
        if (EVP_EncryptFinal_ex(ctx, (unsigned char *)output.mutableBytes + length, &finalLength) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) break;
        output.length = (NSUInteger)length + (NSUInteger)finalLength;
        *authenticationTag = [NSData dataWithBytes:tag length:sizeof(tag)];
        [output appendData:*authenticationTag];
        *cipher = output;
        success = YES;
    } while (NO);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

/// Encrypts a file using AES-GCM and appends the authentication tag at the end of the output file.
/// The generated authentication tag is also returned via the authenticationTag parameter.
/// The output file structure will be: [ciphertext || tag].
///
/// @param fileName The full path to the input plaintext file.
/// @param fileNameCipher The full path to the output file where the ciphertext will be written.
/// @param key The AES key as NSData. Length must match the keyLen parameter.
/// @param keyLen The AES key length in bytes (AES_KEY_128_LENGTH or AES_KEY_256_LENGTH).
/// @param initializationVector The IV/nonce as NSData, recommended 12 bytes for AES-GCM.
/// @param authenticationTag A pointer to an NSData* that will receive the generated authentication tag (typically 16 bytes).
///
/// @return YES if encryption completes successfully, NO otherwise.
- (BOOL)encryptFile:(NSString *)fileName fileNameCipher:(NSString *)fileNameCipher key:(NSData *)key keyLen:(int)keyLen initializationVector:(NSData *)initializationVector authenticationTag:(NSData **)authenticationTag
{
    if (!authenticationTag || !NCValidGCMParameters(key, keyLen, initializationVector, [NSMutableData dataWithLength:AES_GCM_TAG_LENGTH])) return NO;
    // Select cipher based on key length
    const EVP_CIPHER *cipher = NULL;
    if (keyLen == AES_KEY_128_LENGTH) {
        cipher = EVP_aes_128_gcm();
    } else if (keyLen == AES_KEY_256_LENGTH) {
        cipher = EVP_aes_256_gcm();
    } else {
        return NO;
    }

    const unsigned char *cKey = key.bytes;
    const unsigned char *cIV = initializationVector.bytes;
    unsigned char cTag[AES_GCM_TAG_LENGTH] = {0};

    // Create encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NO;

    BOOL success = NO;

    do {
        // Initialize encryption operation
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) <= 0) break;
        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)initializationVector.length, NULL) <= 0) break;
        // Set key and IV
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, cKey, cIV) <= 0) break;

        NSInputStream *inStream = [NSInputStream inputStreamWithFileAtPath:fileName];
        NSOutputStream *outStream = [NSOutputStream outputStreamToFileAtPath:fileNameCipher append:NO];
        [inStream open];
        [outStream open];

        unsigned char inBuf[streamBuffer];
        unsigned char outBuf[streamBuffer + EVP_MAX_BLOCK_LENGTH];
        int outLen = 0;

        // Read plaintext from file, encrypt, and write ciphertext
        while ([inStream hasBytesAvailable]) {
            NSInteger bytesRead = [inStream read:inBuf maxLength:streamBuffer];
            if (bytesRead <= 0) break;

            if (EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, (int)bytesRead) <= 0) break;

            if ([outStream write:outBuf maxLength:outLen] != outLen) break;
        }

        // Finalize encryption (GCM usually produces no extra bytes here)
        if (EVP_EncryptFinal_ex(ctx, outBuf, &outLen) <= 0) break;
        if (outLen > 0 && [outStream write:outBuf maxLength:outLen] != outLen) break;

        // Retrieve the authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(cTag), cTag) <= 0) break;
        *authenticationTag = [NSData dataWithBytes:cTag length:sizeof(cTag)];

        // Append the tag to the end of the output file
        if ([outStream write:cTag maxLength:sizeof(cTag)] != sizeof(cTag)) break;

        success = YES;

        [inStream close];
        [outStream close];
    } while (NO);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

// Decryption data using GCM mode
// Decrypt data using AES-GCM mode
- (BOOL)decryptData:(NSData *)cipher
              plain:(NSMutableData **)plain
                key:(NSData *)key
             keyLen:(int)keyLen
initializationVector:(NSData *)initializationVector
   authenticationTag:(NSData *)authenticationTag
{
    if (!plain) return NO;
    *plain = nil;
    if (!cipher || cipher.length > INT_MAX || !NCValidGCMParameters(key, keyLen, initializationVector, authenticationTag)) return NO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NO;
    // Keep unauthenticated plaintext private until finalization succeeds.
    NSMutableData *candidate = [NSMutableData dataWithLength:cipher.length + EVP_MAX_BLOCK_LENGTH];
    BOOL success = NO;
    int length = 0;
    int finalLength = 0;
    do {
        const EVP_CIPHER *algorithm = keyLen == AES_KEY_128_LENGTH ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
        if (EVP_DecryptInit_ex(ctx, algorithm, NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)initializationVector.length, NULL) != 1) break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.bytes, initializationVector.bytes) != 1) break;
        if (EVP_DecryptUpdate(ctx, candidate.mutableBytes, &length, cipher.bytes, (int)cipher.length) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LENGTH, (void *)authenticationTag.bytes) != 1) break;
        if (EVP_DecryptFinal_ex(ctx, (unsigned char *)candidate.mutableBytes + length, &finalLength) != 1) break;
        candidate.length = (NSUInteger)length + (NSUInteger)finalLength;
        *plain = candidate;
        success = YES;
    } while (NO);
    if (!success) OPENSSL_cleanse(candidate.mutableBytes, candidate.length);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

// Decrypt into a private sibling, then atomically publish authenticated plaintext.
// Supports both older ciphertext-only files and files with an appended 16-byte tag.
- (BOOL)decryptFile:(NSString *)fileName fileNamePlain:(NSString *)fileNamePlain key:(NSData *)key keyLen:(int)keyLen initializationVector:(NSData *)initializationVector authenticationTag:(NSData *)authenticationTag {
    if (!fileName.length || !fileNamePlain.length || !NCValidGCMParameters(key, keyLen, initializationVector, authenticationTag)) return NO;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NO;
    FILE *input = NULL;
    FILE *output = NULL;
    NSString *temporaryPath = nil;
    BOOL authenticated = NO;
    unsigned char inputBuffer[streamBuffer];
    unsigned char outputBuffer[streamBuffer + EVP_MAX_BLOCK_LENGTH];
    do {
        input = fopen(fileName.fileSystemRepresentation, "rb");
        if (!input) break;
        struct stat attributes;
        if (fstat(fileno(input), &attributes) != 0 || !S_ISREG(attributes.st_mode) || attributes.st_size < 0) break;
        off_t remaining = attributes.st_size;
        if (remaining >= AES_GCM_TAG_LENGTH) {
            unsigned char tail[AES_GCM_TAG_LENGTH];
            if (fseeko(input, remaining - AES_GCM_TAG_LENGTH, SEEK_SET) != 0 || fread(tail, 1, sizeof(tail), input) != sizeof(tail)) break;
            if (CRYPTO_memcmp(tail, authenticationTag.bytes, sizeof(tail)) == 0) remaining -= AES_GCM_TAG_LENGTH;
            if (fseeko(input, 0, SEEK_SET) != 0) break;
        }
        const EVP_CIPHER *algorithm = keyLen == AES_KEY_128_LENGTH ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
        if (EVP_DecryptInit_ex(ctx, algorithm, NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)initializationVector.length, NULL) != 1) break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key.bytes, initializationVector.bytes) != 1) break;

        NSString *template = [[fileNamePlain stringByDeletingLastPathComponent] stringByAppendingPathComponent:@".e2ee-decrypt-XXXXXX"];
        char *temporaryName = strdup(template.fileSystemRepresentation);
        if (!temporaryName) break;
        int descriptor = mkstemp(temporaryName); // Exclusive creation with mode 0600.
        if (descriptor >= 0) temporaryPath = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:temporaryName length:strlen(temporaryName)];
        free(temporaryName);
        if (descriptor < 0) break;
        output = fdopen(descriptor, "wb");
        if (!output) { close(descriptor); break; }

        BOOL complete = YES;
        int length = 0;
        while (remaining > 0) {
            size_t count = (size_t)MIN((off_t)sizeof(inputBuffer), remaining);
            if (fread(inputBuffer, 1, count, input) != count ||
                EVP_DecryptUpdate(ctx, outputBuffer, &length, inputBuffer, (int)count) != 1 ||
                fwrite(outputBuffer, 1, (size_t)length, output) != (size_t)length) {
                complete = NO;
                break;
            }
            remaining -= (off_t)count;
        }
        if (!complete || ferror(input)) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LENGTH, (void *)authenticationTag.bytes) != 1) break;
        if (EVP_DecryptFinal_ex(ctx, outputBuffer, &length) != 1) break;
        if (fwrite(outputBuffer, 1, (size_t)length, output) != (size_t)length) break;
        authenticated = YES;
    } while (NO);

    if (input) fclose(input);
    if (output && fclose(output) != 0) authenticated = NO;
    OPENSSL_cleanse(outputBuffer, sizeof(outputBuffer));
    EVP_CIPHER_CTX_free(ctx);
    BOOL success = authenticated && rename(temporaryPath.fileSystemRepresentation, fileNamePlain.fileSystemRepresentation) == 0;
    if (!success && temporaryPath) unlink(temporaryPath.fileSystemRepresentation);
    return success;
}

#
#pragma mark - CMS
#

- (NSData *)generateSignatureCMS:(NSData *)data certificate:(NSString *)certificate privateKey:(NSString *)privateKey userId:(NSString *)userId
{
    unsigned char *pKey = (unsigned char *)[privateKey UTF8String];
    unsigned char *certKey = (unsigned char *)[certificate UTF8String];
    BIO *printBIO = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO *certKeyBIO = BIO_new_mem_buf(certKey, -1);
    if (!certKeyBIO)
        return nil;

    X509 *x509 = PEM_read_bio_X509(certKeyBIO, NULL, 0, NULL);
    if (!x509)
        return nil;

    BIO *pkeyBIO = BIO_new_mem_buf(pKey, -1);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(pkeyBIO, NULL, NULL, NULL);
    if (!key)
        return nil;

    BIO *dataBIO = BIO_new_mem_buf((void*)data.bytes, (int)data.length);

    CMS_ContentInfo *contentInfo = CMS_sign(x509, key, NULL, dataBIO, CMS_DETACHED);
    if (contentInfo == nil)
        return nil;

    // DEBUG CMS_ContentInfo_print_ctx(printBIO, contentInfo, 0, NULL);
    PEM_write_bio_CMS(printBIO, contentInfo);

    BIO *i2dCmsBioOut = BIO_new(BIO_s_mem());
    if (i2d_CMS_bio(i2dCmsBioOut, contentInfo) != 1)
        return nil;

    int len = BIO_pending(i2dCmsBioOut);
    char *keyBytes = malloc(len);
    BIO_read(i2dCmsBioOut, keyBytes, len);

    NSData *i2dCmsData = [NSData dataWithBytes:keyBytes length:len];

    BIO_free(printBIO);
    BIO_free(certKeyBIO);
    BIO_free(pkeyBIO);
    BIO_free(dataBIO);
    BIO_free(i2dCmsBioOut);

    return i2dCmsData;
}

- (BOOL)verifySignatureCMS:(NSData *)cmsContent data:(NSData *)data publicKey:(NSString *)publicKey userId:(NSString *)userId
{
    BIO *dataBIO = BIO_new_mem_buf((void*)data.bytes, (int)data.length);
    BIO *printBIO = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO *cmsBIO = BIO_new_mem_buf(cmsContent.bytes, (int)cmsContent.length);

    CMS_ContentInfo *contentInfo = d2i_CMS_bio(cmsBIO, NULL);

    unsigned char *publicKeyUTF8 = (unsigned char *)[publicKey UTF8String];
    BIO *publicKeyBIO = BIO_new_mem_buf(publicKeyUTF8, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(publicKeyBIO, NULL, NULL, NULL);

    // DEBUG CMS_ContentInfo_print_ctx(printBIO, contentInfo, 0, NULL);

    BOOL verifyResult = CMS_verify(contentInfo, NULL, NULL, dataBIO, NULL, CMS_DETACHED | CMS_NO_SIGNER_CERT_VERIFY);

    if (verifyResult) {

        STACK_OF(X509) *signers = CMS_get0_signers(contentInfo);
        int numSigners = sk_X509_num(signers);

        for (int i = 0; i < numSigners; ++i) {

            X509 *signer = sk_X509_value(signers, i);
            int result = X509_verify(signer, pkey);
            if (result <= 0) {
                verifyResult = false;
                break;
            }

            int cnDataLength = X509_NAME_get_text_by_NID(X509_get_subject_name(signer), NID_commonName, 0, 0);
            cnDataLength += 1;
            NSMutableData* cnData = [NSMutableData dataWithLength:cnDataLength];
            X509_NAME_get_text_by_NID(X509_get_subject_name(signer), NID_commonName, [cnData mutableBytes], cnDataLength);
            NSString *cn = [[NSString alloc] initWithCString:[cnData mutableBytes] encoding:NSUTF8StringEncoding];
            if ([userId isEqualToString:cn]) {
                verifyResult = true;
                break;
            } else {
                verifyResult = false;
            }
        }

        if (signers) {
            sk_X509_free(signers);
        }
        signers = NULL;
    }

    BIO_free(dataBIO);
    BIO_free(printBIO);
    BIO_free(cmsBIO);
    BIO_free(publicKeyBIO);

    return verifyResult;
}

- (BOOL)verifySignatureCMS:(NSData *)cmsContent data:(NSData *)data certificates:(NSArray*)certificates
{
    if (!cmsContent.length || cmsContent.length > INT_MAX || !data || data.length > INT_MAX || !certificates.count) return NO;
    BIO *dataBIO = BIO_new_mem_buf(data.bytes, (int)data.length);
    BIO *cmsBIO = BIO_new_mem_buf(cmsContent.bytes, (int)cmsContent.length);
    CMS_ContentInfo *contentInfo = cmsBIO ? d2i_CMS_bio(cmsBIO, NULL) : NULL;
    STACK_OF(X509) *signers = NULL;
    BOOL trustedSigner = NO;
    if (dataBIO && contentInfo && CMS_verify(contentInfo, NULL, NULL, dataBIO, NULL, CMS_DETACHED | CMS_NO_SIGNER_CERT_VERIFY) == 1) {
        // These are the actual certificates used for mathematical signature verification.
        // Issuer/serial comparison alone does not bind a signature to an expected key.
        signers = CMS_get0_signers(contentInfo);
        for (NSString *certificate in certificates) {
            if (![certificate isKindOfClass:[NSString class]]) continue;
            NSData *pem = [certificate dataUsingEncoding:NSUTF8StringEncoding];
            if (!pem.length || pem.length > INT_MAX) continue;
            BIO *expectedBIO = BIO_new_mem_buf(pem.bytes, (int)pem.length);
            X509 *expectedCertificate = expectedBIO ? PEM_read_bio_X509(expectedBIO, NULL, NULL, NULL) : NULL;
            EVP_PKEY *expectedKey = expectedCertificate ? X509_get_pubkey(expectedCertificate) : NULL;
            if (!expectedCertificate && expectedBIO) {
                BIO_reset(expectedBIO);
                expectedKey = PEM_read_bio_PUBKEY(expectedBIO, NULL, NULL, NULL);
            }
            for (int index = 0; expectedKey && index < sk_X509_num(signers); ++index) {
                EVP_PKEY *signerKey = X509_get_pubkey(sk_X509_value(signers, index));
                if (signerKey && EVP_PKEY_eq(signerKey, expectedKey) == 1) trustedSigner = YES;
                EVP_PKEY_free(signerKey);
            }
            EVP_PKEY_free(expectedKey);
            X509_free(expectedCertificate);
            BIO_free(expectedBIO);
            if (trustedSigner) break;
        }
    }
    sk_X509_free(signers); // CMS owns the certificates themselves.
    CMS_ContentInfo_free(contentInfo);
    BIO_free(dataBIO);
    BIO_free(cmsBIO);
    return trustedSigner;
}

#
#pragma mark - Utility
#

- (void)Encodedkey:(NSString **)key initializationVector:(NSString **)initializationVector
{
    NSData *keyData = [self generateKey:AES_KEY_128_LENGTH];
    NSData *ivData = [self generateIV:AES_IVEC_LENGTH];

    *key = [keyData base64EncodedStringWithOptions:0];
    *initializationVector = [ivData base64EncodedStringWithOptions:0];
}

- (NSString *)createSHA256:(NSData *)data
{
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (unsigned int)data.length, digest);
    NSMutableString* output = [NSMutableString  stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];

    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}

- (NSString *)createSHA512:(NSString *)string
{
    const char *cstr = [string cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:string.length];

    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(data.bytes, (unsigned int)data.length, digest);
    NSMutableString* output = [NSMutableString  stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];

    for(int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}

- (NSData *)generateIV:(int)length
{
    NSMutableData *ivData = [NSMutableData dataWithLength:length];
    (void)SecRandomCopyBytes(kSecRandomDefault, length, ivData.mutableBytes);

    return ivData;
}

- (NSData *)generateSalt:(int)length
{
    NSMutableData *saltData = [NSMutableData dataWithLength:length];
    (void)SecRandomCopyBytes(kSecRandomDefault, length, saltData.mutableBytes);
    
    return saltData;
}

- (NSData *)generateKey:(int)length
{
    NSMutableData *keyData = [NSMutableData dataWithLength:length];
    unsigned char *pKeyData = [keyData mutableBytes];

    RAND_bytes(pKeyData, length);

    return keyData;
}

- (NSData *)generateKey
{
    NSMutableData *keyData = [NSMutableData dataWithLength:AES_KEY_128_LENGTH];
    unsigned char *pKeyData = [keyData mutableBytes];

    RAND_bytes(pKeyData, AES_KEY_128_LENGTH);

    return keyData;
}

- (NSString *)getSHA1:(NSString *)input
{
    const char *cstr = [input cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [NSData dataWithBytes:cstr length:input.length];
    
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(data.bytes, (unsigned int)data.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    return output;
}

- (NSString *)hexadecimalString:(NSData *)input
{
    const unsigned char *dataBuffer = (const unsigned char *) [input bytes];
    
    if (!dataBuffer) {
        return [NSString string];
    }
    
    NSUInteger dataLength = [input length];
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i) {
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long) dataBuffer[i]]];
    }
    
    return [NSString stringWithString:hexString];
}

- (NSString *)derToPemPrivateKey:(NSString *)input
{
    NSInteger substringLength = 65;

    NSMutableString *result = [NSMutableString stringWithString: input];
    for(long i=substringLength;i<=input.length;i++) {
        [result insertString: @"\n" atIndex: i];
        i+=substringLength;
    }
    
    [result insertString: @"-----BEGIN PRIVATE KEY-----\n" atIndex: 0];
    [result appendString:@"\n-----END PRIVATE KEY-----\n"];

    return result;
}

- (NSString *)pubKeyToString:(EVP_PKEY *)pubkey
{
    if (!pubkey) return nil;
    BIO *output = BIO_new(BIO_s_mem());
    if (!output) return nil;
    NSString *result = nil;
    if (PEM_write_bio_PUBKEY(output, pubkey) == 1) {
        char *bytes = NULL;
        long length = BIO_get_mem_data(output, &bytes);
        if (length > 0) result = [[NSString alloc] initWithBytes:bytes length:(NSUInteger)length encoding:NSUTF8StringEncoding];
    }
    BIO_free(output);
    return result;
}

@end
