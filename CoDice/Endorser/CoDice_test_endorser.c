#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/x509.h>
#include "../CoDice_layers.h"

int main(int argc, char* argv[]){
    if (argc != 2){
        printf("Usage: %s <Manifest File>\n", argv[0]);
        return 1;
    }
    int seed[64];
    size_t seed_len = sizeof(seed);
    RAND_bytes((unsigned char*)seed, sizeof(seed));
    X509* x509 = X509_new();
    EC_KEY* endorserKey = EC_KEY_new();

    printf("Generating endorser key pair...\n");
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
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, eckey);
    printf("Endorser key pair generated successfully.\n");
    if (!pkey) {
        fprintf(stderr, "Failed to create EVP_PKEY from EC_KEY\n");
        EC_KEY_free(eckey);
        return 1;
    }

    printf("Generating endorser certificate...\n");
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"ECA Layer Cert", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    X509_set_pubkey(x509, pkey);
    X509_sign(x509, pkey, EVP_sha256());
    PEM_write_X509(stdout, x509);
    printf("Signed endorser certificate generated successfully.\n");
    if (!x509) {
        fprintf(stderr, "Failed to create X509 certificate\n");
        EVP_PKEY_free(pkey);
        return 1;
    }
    printf("Writing signed endorser certificate to Endorser_Certificate.pem\n");
    writeCertificateToFile(x509, "Endorser_Certificate.pem");
    printf("Writing signed endorser public key to Endorser_Public_Key.pem\n");
    writePublicKeyToFile(pkey, "Endorser_Public_Key.pem");
    printf("Endorser certificate and public key written successfully.\n");
    X509_free(x509);
    EVP_PKEY_free(pkey);

    const char* manifestFileName = argv[1];
    int manifestFileSize = getFileSize(manifestFileName);
    if (manifestFileSize == -1) {
        fprintf(stderr, "Error getting size of manifest file %s\n", manifestFileName);
        return 1;
    }
    FILE* manifestFile = fopen(manifestFileName, "rb");
    if (manifestFile == NULL) {
        perror("Error opening manifest file");
        return 1;
    }
    char* manifestData = (char*)malloc(manifestFileSize);
    if (manifestData == NULL) {
        perror("Error allocating memory for manifest data");
        fclose(manifestFile);
        return 1;
    }
    readData(manifestFile, manifestData, manifestFileSize);
    FILE* outputFile = fopen("Endorser_Manifest.diag", "wb");
    if (outputFile == NULL) {
        perror("Error opening output file");
        free(manifestData);
        fclose(manifestFile);
        return 1;
    }
    printf("Writing endorser manifest data to Endorser_Manifest.diag\n");
    if (fwrite(manifestData, 1, manifestFileSize, outputFile) != manifestFileSize) {
        perror("Error writing to output file");
        free(manifestData);
        fclose(outputFile);
        fclose(manifestFile);
        return 1;
    } 

    return 0;

}