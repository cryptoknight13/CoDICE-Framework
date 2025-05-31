#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/x509.h>
#include "../CoDice_layers.h"


int main(int argc, char* argv[]){
    if(argc != 7){
        printf("Usage: %s <Manifest File>  <Attester Certificate File> <Attester Public Key File> <Attester Measurement File> <Endorser Certificate File> <Endorser Public Key File>\n", argv[0]);
        return 1;
    }
    X509* endorserCert = X509_new();
    EVP_PKEY* endorserPubKey = EVP_PKEY_new();
    printf("Reading endorser certificate from file: %s\n", argv[5]);
    readCertificateFromFile(argv[5], &endorserCert);
    printf("Reading endorser public key from file: %s\n", argv[6]);
    readPublicKeyFromFile(argv[6], &endorserPubKey);
    if (endorserCert == NULL || endorserPubKey == NULL) {
        fprintf(stderr, "Error reading endorser certificate or public key\n");
        return 1;
    }
    printf("Verifying endorser certificate...\n");
    int verifyEndorserCert = X509_verify(endorserCert, endorserPubKey);
    if (verifyEndorserCert != 1) {
        fprintf(stderr, "Endorser certificate verification failed\n");
        EVP_PKEY_free(endorserPubKey);
        X509_free(endorserCert);
        return 1;
    }
    printf("Endorser certificate verification succeeded\n");
    EVP_PKEY_free(endorserPubKey);
    X509_free(endorserCert);
    const char* manifestFileName = argv[1];
    const char* attesterCertFileName = argv[2];
    const char* attesterPublicKeyFileName = argv[3];
    const char* attesterMeasurementFileName = argv[4];
    int manifestFileSize = getFileSize(manifestFileName);
    FILE* manifestFile = fopen(manifestFileName, "rb");
    const char* manifestData = (char*)malloc(manifestFileSize);
    printf("Reading endorser manifest file: %s\n", manifestFileName);
    readData(manifestFile, manifestData, manifestFileSize);
    X509* attesterCert = X509_new();
    EVP_PKEY* attesterPubKey = EVP_PKEY_new(); 
    printf("Reading attester certificate from file: %s\n", attesterCertFileName);
    readCertificateFromFile(attesterCertFileName, &attesterCert);
    printf("Reading attester public key from file: %s\n", attesterPublicKeyFileName);
    readPublicKeyFromFile(attesterPublicKeyFileName, &attesterPubKey);
    if (attesterCert == NULL || attesterPubKey == NULL) {
        fprintf(stderr, "Error reading attester certificate or public key\n");
        return 1;
    }
    printf("Verifying attester certificate...\n");
    int verifyCert = X509_verify(attesterCert, attesterPubKey);
    if (verifyCert != 1) {
        fprintf(stderr, "Attester certificate verification failed\n");
        EVP_PKEY_free(attesterPubKey);
        X509_free(attesterCert);
        return 1;
    }
    printf("Attester certificate verification succeeded\n");
    EVP_PKEY_free(attesterPubKey);
    X509_free(attesterCert);

    int attesterDataSize = getFileSize(attesterMeasurementFileName);
    FILE* attesterDataFile = fopen(attesterMeasurementFileName, "rb");
    if (attesterDataFile == NULL) {
        perror("Error opening attester measurement data file");
        return 1;
    }
    char* attesterData = (char*)malloc(attesterDataSize);
    if (attesterData == NULL) {
        perror("Error allocating memory for attester data");
        return 1;
    }
    printf("Reading attester evidence data from file: %s\n", attesterMeasurementFileName);
    readData(attesterDataFile, attesterData, attesterDataSize);
    if (attesterDataSize != manifestFileSize){
        fprintf(stderr, "Attester data size does not match manifest file size. Failed verification\n");
        return 1;
    }
    printf("Comparing attester evidence with manifest data...\n");
    int compareManifest = compareEvidenceWithManifest(attesterData, attesterDataSize, manifestData, manifestFileSize);
    
    if (compareManifest == 0){
        fprintf(stderr, "Attester data is a different size than manifest. Failed verification\n");
        return 1;
    }
    if(compareManifest == -1){
        fprintf(stderr, "Attester data does not match manifest data. Failed verification\n");
        return 1;
    }
    
    printf("Attester evidence matches manifest data. Verification succeeded\n");

    return 0;
}