#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "CoDice_layers.h"
#include <openssl/rand.h>


void readData(FILE* file, char* data, int size){
    for(int i = 0; i < size; i++){
        data[i] = fgetc(file);
    }
    fclose(file);
}

int getFileSize(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fclose(file);

    return size;
}

void printer(char* string, char* outFileName, int len){
    FILE* file = fopen(outFileName, "w");
    //printf("Len entered  = %d\n", len);
    if(file == NULL){
        printf("Couldn't find file\n");
    }
    //printf("strlen returned: %d\n", len);
    for(int i = 0; i < len; i++){
        //printf("%c", string[i]);
        fprintf(file, "%c", string[i]);
    }
    //printf("\n");
    fclose(file);
}

void generateHash(const char* layerData, int layerSize, unsigned char* hash){
    SHA512((const unsigned char*)layerData, layerSize, hash);
}

//Used for verifier when the data is in one manifest file
void generateLayersVerifier(char* data, int layerSizes[], DICE_LAYERS* layers){
    char* TempTCIOne = (char*)malloc(layerSizes[0]);
    char* TempTCITwo = (char*)malloc(layerSizes[1]);
    char* TempTCIThree = (char*)malloc(layerSizes[2]);
    char* TempTCIFour = (char*)malloc(layerSizes[3]);
    memcpy(TempTCIOne, data, layerSizes[0]);
    memcpy(TempTCITwo, data + layerSizes[0], layerSizes[1]);
    memcpy(TempTCIThree, data + layerSizes[0] + layerSizes[1], layerSizes[2]);
    memcpy(TempTCIFour, data + layerSizes[0] + layerSizes[1] + layerSizes[2], layerSizes[3]);



    layers->TCIOne = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    layers->TCITwo = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    layers->TCIThree = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    layers->TCIFour = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    if(layers->TCIOne == NULL || layers->TCITwo == NULL || layers->TCIThree == NULL || layers->TCIFour == NULL){
        perror("Error allocating memory");
        return;
    }

    generateHash(TempTCIOne, layerSizes[0], layers->TCIOne);
    generateHash(TempTCITwo, layerSizes[1], layers->TCITwo);
    generateHash(TempTCIThree, layerSizes[2], layers->TCIThree);
    generateHash(TempTCIFour, layerSizes[3], layers->TCIFour);
    free(TempTCIOne);
    free(TempTCITwo);
    free(TempTCIThree);
    free(TempTCIFour);
}

void generateLayersAttester(char* data, int layerCount, DICE_LAYERS* layers){
    layers->TCIs = malloc(layerCount * sizeof(unsigned char*));
    for(int i = 0; i < layerCount; i++){
        layers->TCIs[i] = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
        if(layers->TCIs[i] == NULL){
            perror("Error allocating memory for TCI");
            return;
        }
        int offset = 0;
        for(int j = 0; j < i; j++){
            offset += layers->sizes[j];
        }
        generateHash(&data[offset], layers->sizes[i], layers->TCIs[i]);
    }

}

//Used by an attester to gather data for each dice layer when the data is in separate files
void generateLayers(char* data, int layerSizes[], DICE_LAYERS* layers){
    layers->TCIOne = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    layers->TCITwo = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    layers->TCIThree = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    layers->TCIFour = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);
    if(layers->TCIOne == NULL || layers->TCITwo == NULL || layers->TCIThree == NULL || layers->TCIFour == NULL){
        perror("Error allocating memory");
        return;
    }
    printf("%p \n", &data[0]);
    generateHash(&data[0], layerSizes[0], layers->TCIOne);
    generateHash(&data[layerSizes[0]], layerSizes[1], layers->TCITwo);
    generateHash(&data[layerSizes[0] + layerSizes[1]], layerSizes[2], layers->TCIThree);
    generateHash(&data[layerSizes[0] + layerSizes[1] + layerSizes[2]], layerSizes[3], layers->TCIFour);
}

void generateCDI(uint8_t* cdiBuffer, size_t cdiSize, unsigned char* tci, size_t tciSize){
    uint8_t* cdiAndTCI = (uint8_t*)malloc(cdiSize + SHA512_DIGEST_LENGTH);
    if(cdiAndTCI == NULL){
        perror("Error allocating memory");
        return;
    }
    memcpy(cdiAndTCI, tci, tciSize);
    memcpy(cdiAndTCI + tciSize, cdiBuffer, cdiSize);
    generateHash((const char*)cdiAndTCI, cdiSize + tciSize, cdiBuffer);
    free(cdiAndTCI);
}

void printCDI(uint8_t* cdi, size_t size){
    printf("\n---------BEGIN CDI---------\n");
    for(int i = 0; i < size; i++){
        printf("%02x", cdi[i]);
    }
    printf("\n----------END CDI----------\n");
}

EC_KEY* generateKeyPair(unsigned char* seed, size_t seed_len){
    unsigned char privkey_bytes[32];
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return NULL;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, seed, seed_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, "ECA Derivation", strlen("ECA Derivation")) <= 0) {
        fprintf(stderr, "HKDF parameter setup failed\n");
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    size_t outlen = sizeof(privkey_bytes);
    if (EVP_PKEY_derive(pctx, privkey_bytes, &outlen) <= 0) {
        fprintf(stderr, "HKDF derive failed\n");
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    BIGNUM *priv_bn = BN_bin2bn(privkey_bytes, sizeof(privkey_bytes), NULL);
    if (!priv_bn) return NULL;

    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!eckey) {
        BN_free(priv_bn);
        return NULL;
    }

    if (!EC_KEY_set_private_key(eckey, priv_bn)) {
        fprintf(stderr, "Failed to set private key\n");
        EC_KEY_free(eckey);
        BN_free(priv_bn);
        return NULL;
    }

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    EC_POINT *pubkey_point = EC_POINT_new(group);
    if (!pubkey_point || !EC_POINT_mul(group, pubkey_point, priv_bn, NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to derive public key\n");
        EC_KEY_free(eckey);
        BN_free(priv_bn);
        EC_POINT_free(pubkey_point);
        return NULL;
    }

    if (!EC_KEY_set_public_key(eckey, pubkey_point)) {
        fprintf(stderr, "Failed to set public key\n");
        EC_POINT_free(pubkey_point);
        EC_KEY_free(eckey);
        BN_free(priv_bn);
        return NULL;
    }

    EC_POINT_free(pubkey_point);
    BN_free(priv_bn);
    return eckey;
}

EVP_PKEY* strip_private_key(EVP_PKEY* key_with_private) {
    if (!key_with_private || EVP_PKEY_base_id(key_with_private) != EVP_PKEY_EC) {
        return NULL;
    }

    EC_KEY* full_ec = EVP_PKEY_get0_EC_KEY(key_with_private);
    if (!full_ec) return NULL;

    // Create a new EC_KEY and copy only the public part
    const EC_GROUP* group = EC_KEY_get0_group(full_ec);
    const EC_POINT* pub_point = EC_KEY_get0_public_key(full_ec);

    EC_KEY* pub_ec = EC_KEY_new();
    EC_KEY_set_group(pub_ec, group);
    EC_KEY_set_public_key(pub_ec, pub_point);

    EVP_PKEY* pub_only = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pub_only, pub_ec); // transfers ownership of pub_ec

    return pub_only;
}

void generateCertificate(X509* x509, EVP_PKEY* pkey, unsigned char* nonce, size_t nonce_len,
                        unsigned char* TCI, size_t tciSize){
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"ECA Layer Cert", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509_set_pubkey(x509, pkey);
    // unsigned char nonce[32];
    // if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
    //     fprintf(stderr, "Error generating nonce\n");
    //     return;
    // }
    ASN1_OCTET_STRING *nonce_asn1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(nonce_asn1, nonce, nonce_len);
    X509_EXTENSION *ext = X509_EXTENSION_create_by_NID(NULL, NID_netscape_comment, 0, nonce_asn1);
    X509_add_ext(x509, ext, -1);
    ASN1_OCTET_STRING_free(nonce_asn1);
    X509_EXTENSION_free(ext);

    ASN1_OCTET_STRING *tci_asn1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(tci_asn1, TCI, tciSize);
    X509_EXTENSION *tci_ext = X509_EXTENSION_create_by_NID(NULL, NID_subject_key_identifier, 0, tci_asn1);
    X509_add_ext(x509, tci_ext, -1);
    ASN1_OCTET_STRING_free(tci_asn1);
    X509_EXTENSION_free(tci_ext);                  

    // X509_sign(x509, pkey, EVP_sha256());
}

int verifyCertificate(X509* x509, EVP_PKEY* expected_pkey, EVP_PKEY* previous_pkey,
                    unsigned char* expectedNonce, size_t nonce_len,
                    unsigned char* expextedTCI, size_t tciSize){
    if (!x509 || !expected_pkey) {
        fprintf(stderr, "Invalid input to verifyCertificate\n");
        return -1;
    }

    EVP_PKEY *cert_pubkey = X509_get_pubkey(x509);
    if (!cert_pubkey) {
        fprintf(stderr, "Failed to extract public key from certificate\n");
        return -1;
    }

    int cmp = EVP_PKEY_cmp(cert_pubkey, expected_pkey);
    int result = X509_verify(x509, previous_pkey);
    if(result == 1){
        printf("Certificate signature verified\n");
    } else {
        printf("Certificate signature verification failed\n");
    }
    int nonce_cmp = -1;
    int tci_cmp = -1;
    int ext_count = X509_get_ext_count(x509);
    for (int i = 0; i < ext_count; i++){
        X509_EXTENSION * ext = X509_get_ext(x509, i);
        ASN1_OBJECT * obj = X509_EXTENSION_get_object(ext);
        int nid = OBJ_obj2nid(obj);

        if(nid == NID_netscape_comment){
            ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);

            if(data && ASN1_STRING_length(data) == (int)nonce_len) {
                const unsigned char* cert_nonce = ASN1_STRING_get0_data(data);
                nonce_cmp = memcmp(cert_nonce, expectedNonce, nonce_len);
                if (nonce_cmp == 0) {
                    // printf("Nonce matches\n");
                } else {
                    // printf("Nonce does not match\n");
                }
            }
        }
        if(nid == NID_subject_key_identifier){
            ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(ext);
            if(data && ASN1_STRING_length(data) == (int)tciSize) {
                const unsigned char* cert_tci = ASN1_STRING_get0_data(data);
                tci_cmp = memcmp(cert_tci, expextedTCI, tciSize);
                if (tci_cmp == 0) {
                    // printf("TCI matches\n");
                } else {
                    // printf("TCI does not match\n");
                }
            }
        }

    }
    EVP_PKEY_free(cert_pubkey);  // cleanup

    if (cmp == 1 && result == 1 && nonce_cmp == 0) {
        return 1;
    } else if (cmp != 1 || result != 1 || nonce_cmp != 0) {
        return -1;
    } else {
        printf("Error comparing public keys: %d\n", cmp);
        return 0;
    }
}

void runDiceLayer(uint8_t* nextCDI, size_t cdiSize, unsigned char* currentTCI,
     unsigned char* nextTCI, size_t tciSize, X509** x509Current, int writeCert, 
     int verifyCert, unsigned char* nonce, size_t nonce_len, EVP_PKEY** previousPubKey, int writePubKey, int finalLayer, int currentLayer){

    uint8_t* previousCDI = (uint8_t*)malloc(cdiSize);
    memcpy(previousCDI, nextCDI, cdiSize);
    if(verifyCert == 1){
        unsigned char* seed = (unsigned char*)malloc(cdiSize);
        size_t seed_len = cdiSize;
        if(seed == NULL){
            perror("Error allocating memory");
            return;
        }
        memcpy(seed, nextCDI, cdiSize);
        EC_KEY* eckey = generateKeyPair(seed, seed_len);
        if(eckey == NULL){
            printf("Key pair generation failed\n");
            free(seed);
            return;
        }
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, eckey);
        if(verifyCertificate(*x509Current, pkey, *previousPubKey, nonce, nonce_len, currentTCI, tciSize) == -1){
            // printf("Certificate verification failed\n");
            EVP_PKEY_free(pkey);
            free(seed);
            return;
        }
        // printf("Certificate verification successful\n");
        EVP_PKEY_free(pkey);
        free(seed);
    }
    generateCDI(nextCDI, cdiSize, nextTCI, tciSize);

    if(currentLayer == 0){
        printf("Dice Layer: CDI %d generated\n", currentLayer);
    }
    else{
        printf("Layer %d: CDI %d generated\n", currentLayer - 1, currentLayer);
    }


    // printCDI(nextCDI, cdiSize);

    if(x509Current == NULL){
        // printf("Skipping certificate generation\n");
        free(previousCDI);
        return;
    }

    if(finalLayer == 0){       
        unsigned char* seed = (unsigned char*)malloc(cdiSize);
        unsigned char* seedPrevious = (unsigned char*)malloc(cdiSize);

        size_t seed_len = cdiSize;
        if(seed == NULL){
            perror("Error allocating memory");
            return;
        }
        
        memcpy(seed, nextCDI, cdiSize);
        memcpy(seedPrevious, previousCDI, cdiSize);
        EC_KEY* eckey = generateKeyPair(seed, seed_len);
        EC_KEY* eckeyPrevious = generateKeyPair(seedPrevious, seed_len);
        if(eckey == NULL){
            printf("Key pair generation failed\n");
            free(seed);
            return;
        }
        if (RAND_bytes(nonce, nonce_len) != 1) {
        fprintf(stderr, "Nonce generation failed\n");
        return;
        }
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY *pkeyPrevious = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, eckey);
        EVP_PKEY_assign_EC_KEY(pkeyPrevious, eckeyPrevious);
        X509 *x509 = X509_new();
        generateCertificate(x509, pkey, nonce, nonce_len, nextTCI, tciSize);
        X509_sign(x509, pkeyPrevious, EVP_sha256());
        *previousPubKey = strip_private_key(pkeyPrevious);
        *x509Current = x509;
        // printf("Layer %d key pairs generated \n", currentLayer + 1);
        // PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
        // PEM_write_PUBKEY(stdout, pkey);
        printf("Layer %d: key pairs generated\n", currentLayer - 1);
        // PEM_write_PrivateKey(stdout, pkeyPrevious, NULL, NULL, 0, NULL, NULL);
        // PEM_write_PUBKEY(stdout, pkeyPrevious);
        printf("Layer %d: certificate %d generated and signed\n", currentLayer-1, currentLayer);
        // PEM_write_X509(stdout, x509);
        if(writeCert == 1){
            printf("Writing certificate to ../Verifier/Attester_Cert.pem\n");
            writeCertificateToFile(x509, "../Verifier/Attester_Cert.pem");
        }
        if(writePubKey == 1){
            printf("Writing public key to ../Verifier/Attester_Public_Key.pem\n");
            writePublicKeyToFile(*previousPubKey, "../Verifier/Attester_Public_Key.pem");
        }
        free(previousCDI);
        free(seed);
        free(seedPrevious);
        EVP_PKEY_free(pkeyPrevious);
    }

    else if(finalLayer == 1){
        unsigned char* seed = (unsigned char*)malloc(cdiSize);

        size_t seed_len = cdiSize;
        if(seed == NULL){
            perror("Error allocating memory");
            return;
        }
        
        memcpy(seed, nextCDI, cdiSize);
        EC_KEY* eckey = generateKeyPair(seed, seed_len);
        if(eckey == NULL){
            printf("Key pair generation failed\n");
            free(seed);
            return;
        }
        if (RAND_bytes(nonce, nonce_len) != 1) {
        fprintf(stderr, "Nonce generation failed\n");
        return;
        }
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, eckey);
        printf("Final Layer: Attestation key pair generated\n");
        X509 *x509 = X509_new();
        unsigned char* tempTCI = (unsigned char*)malloc(tciSize);
        for(int i = 0; i < tciSize; i++){
            tempTCI[i] = 'x';
        }
        generateCertificate(x509, pkey, nonce, nonce_len, tempTCI, tciSize);
        X509_sign(x509, pkey, EVP_sha256());
        *previousPubKey = strip_private_key(pkey);
        *x509Current = x509;
        // printf("Final layer key pairs:\n");
        // PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
        // PEM_write_PUBKEY(stdout, pkey);
        printf("Final layer: Attester signed certificate:\n");
        PEM_write_X509(stdout, x509);
        if(writeCert == 1){
            printf("Writing certificate to Attester_Cert.pem\n");
            writeCertificateToFile(x509, "Attester_Cert.pem");
        }
        if(writePubKey == 1){
            printf("Writing public key to Attester_Public_Key.pem\n");
            writePublicKeyToFile(*previousPubKey, "Attester_Public_Key.pem");
        }
        free(previousCDI);
        free(seed);
    } 
}

void runDiceLayerVerifier(uint8_t* nextCDI, size_t cdiSize,
     unsigned char* nextTCI, size_t tciSize){
    generateCDI(nextCDI, cdiSize, nextTCI, tciSize);
    printCDI(nextCDI, cdiSize);
    printf("\n");
}

int hexCharToValue(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Converts a hex string to a binary buffer
// hex must be a null-terminated 128-char string
// out must be at least 64 bytes
int hexStringToBytes(const char* hex, uint8_t* out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || out_len < hex_len / 2) return -1;

    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hexCharToValue(hex[i * 2]);
        int lo = hexCharToValue(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;

        out[i] = (hi << 4) | lo;
    }

    return hex_len / 2;  // number of bytes written
}

int compareCDIS(uint8_t* cdi1, uint8_t* cdi2, size_t size){
    for(int i = 0; i < size; i++){
        if(cdi1[i] != cdi2[i]){
            return -1;
        }
    }
    return 1;
}

void writeCertificateToFile(X509* x509, const char* filename) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file for writing");
        return;
    }
    if (PEM_write_X509(file, x509) <= 0) {
        fprintf(stderr, "Error writing X509 certificate to file\n");
    }
    fclose(file);
}

void writePublicKeyToFile(EVP_PKEY* pkey, const char* filename) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file for writing");
        return;
    }
    if (PEM_write_PUBKEY(file, pkey) <= 0) {
        fprintf(stderr, "Error writing public key to file\n");
    }
    fclose(file);
}

void readCertificateFromFile(const char* filename, X509** x509) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening certificate file");
        return;
    }
    *x509 = PEM_read_X509(file, NULL, NULL, NULL);
    if (*x509 == NULL) {
        fprintf(stderr, "Error reading X509 certificate from file\n");
    }
    fclose(file);
}
void readPublicKeyFromFile(const char* filename, EVP_PKEY** pkey) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening public key file");
        return;
    }
    *pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if (*pkey == NULL) {
        fprintf(stderr, "Error reading public key from file\n");
    }
    fclose(file);
}

int compareEvidenceWithManifest(const char* evidenceData, const int evidenceSize,
                                const char* manifestData, const int manifestSize) {
    if (evidenceSize != manifestSize) {
        return 0; // Sizes do not match
    }
    return memcmp(evidenceData, manifestData, evidenceSize) == 0 ? 1 : -1;
}

// Background white screenshots
// Fix signing
// Put key pairs, tcis and cdis for afm bmc and pch 
// Create readme