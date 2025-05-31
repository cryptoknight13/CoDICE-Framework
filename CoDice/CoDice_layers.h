// AMI_dice_layers.h

#ifndef AMI_DICE_LAYERS_H
#define AMI_DICE_LAYERS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// DICE_LAYERS structure to hold TCI hashes
typedef struct {
    unsigned char** TCIs;
    int* sizes;
    unsigned char* TCIOne;
    unsigned char* TCITwo;
    unsigned char* TCIThree;
    unsigned char* TCIFour;
} DICE_LAYERS;

// File and data handling
void readData(FILE* file, char* data, int size);
int getFileSize(const char* filename);
void printer(char* string, char* outFileName, int len);

// Hash generation
void generateHash(const char* layerData, int layerSize, unsigned char* hash);

// TCI layer generation
void generateLayersAttester(char* data, int layerCount, DICE_LAYERS* layers);
void generateLayers(char* data, int layerSizes[], DICE_LAYERS* layers);
void generateLayersVerifier(char* data, int layerSizes[], DICE_LAYERS* layers);

// CDI management
void generateCDI(uint8_t* cdiBuffer, size_t cdiSize, unsigned char* tci, size_t tciSize);
void printCDI(uint8_t* cdi, size_t size);
int compareCDIS(uint8_t* cdi1, uint8_t* cdi2, size_t size);

// Key generation and manipulation
EC_KEY* generateKeyPair(unsigned char* seed, size_t seed_len);
EVP_PKEY* strip_private_key(EVP_PKEY* key_with_private);

// Certificate generation and verification
void generateCertificate(X509* x509, EVP_PKEY* pkey, unsigned char* nonce, size_t nonce_len,
                         unsigned char* TCI, size_t tciSize);
int verifyCertificate(X509* x509, EVP_PKEY* expected_pkey, EVP_PKEY* previous_pkey,
                      unsigned char* expectedNonce, size_t nonce_len,
                      unsigned char* expectedTCI, size_t tciSize);
void writeCertificateToFile(X509* x509, const char* filename);
void writePublicKeyToFile(EVP_PKEY* pkey, const char* filename);

// DICE layer attestation logic
void runDiceLayer(uint8_t* nextCDI, size_t cdiSize, unsigned char* currentTCI,
     unsigned char* nextTCI, size_t tciSize, X509** x509Current, int writeCert, 
     int verifyCert, unsigned char* nonce, size_t nonce_len, EVP_PKEY** previousPubKey, int writePubKey, int finalLayer, int currentLayer);
void runDiceLayerVerifier(uint8_t* nextCDI, size_t cdiSize,
                          unsigned char* nextTCI, size_t tciSize);

// Hex utility
int hexCharToValue(char c);
int hexStringToBytes(const char* hex, uint8_t* out, size_t out_len);

void readPublicKeyFromFile(const char* filename, EVP_PKEY** pkey);
void readCertificateFromFile(const char* filename, X509** x509);

int compareEvidenceWithManifest(const char* evidenceData, const int evidenceSize,
                                const char* manifestData, const int manifestSize);

#endif // AMI_DICE_LAYERS_H
