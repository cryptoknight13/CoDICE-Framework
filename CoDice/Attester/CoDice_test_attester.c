#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/x509.h>
#include "../CoDice_layers.h"

int main(int argc, char* argv[]){
    int fileCount = argc - 1;
    int fileSizes[fileCount];
    int totalSize = 0;
    DICE_LAYERS attesterLayers;
    attesterLayers.sizes = (int*)malloc(fileCount * sizeof(int));
    for(int i = 1; i < argc; i++){
        fileSizes[i - 1] = getFileSize(argv[i]);
        if(fileSizes[i - 1] == -1){
            fprintf(stderr, "Error getting size of file %s\n", argv[i]);
            return 1;
        }
        attesterLayers.sizes[i - 1] = fileSizes[i - 1];
        if(fileSizes[i - 1] <= 0){
            fprintf(stderr, "File %s has invalid size: %d\n", argv[i], fileSizes[i - 1]);
            return 1;
        }
        totalSize += fileSizes[i - 1];
    }
    char* tempData;
    char* data = (char*)malloc(totalSize);
    for(int i = 1; i < argc; i++){
        FILE* file = fopen(argv[i], "rb");
        if(file == NULL){
            perror("Error opening file");
            return 1;
        }
        tempData = (char*)malloc(fileSizes[i - 1]);
        if(tempData == NULL){
            perror("Error allocating memory");
            fclose(file);
            return 1;
        }
        readData(file, tempData, fileSizes[i - 1]);
        int offset = 0;
        for(int j = 0; j < i - 1; j++){
            offset += fileSizes[j];
        }
        memcpy(data + offset, tempData, fileSizes[i - 1]);
        free(tempData);
    }

    generateLayersAttester(data, fileCount, &attesterLayers);
    // printf("Attester Layers:\n");
    // for(int i = 0; i < fileCount; i++){
    //     printf("Layer %d TCI: ", i);
    // }
    unsigned char nonce[32];
    size_t nonce_len = sizeof(nonce);
    if (RAND_bytes(nonce, nonce_len) != 1) {
        fprintf(stderr, "Nonce generation failed\n");
        return 1;
    }
    uint8_t nextCDI[64] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
                                        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','1', '2', 
                                        '3', '4', '5', '6', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 
                                        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 
                                        'y', 'z','1', '2', '3', '4', '5', '6'};
    unsigned char* FSD = (unsigned char*)malloc(64);
    for(int i = 0; i < 64; i++){
        FSD[i] = '1';
    }
    X509* x509 = X509_new();
    EVP_PKEY* previousPubKey = EVP_PKEY_new();

    for(int i = 0; i < fileCount + 1; i++){
        
        if (i == 0){
            runDiceLayer(nextCDI, 64, attesterLayers.TCIs[0], attesterLayers.TCIs[0], SHA512_DIGEST_LENGTH, NULL, 0, 0, nonce, nonce_len, &previousPubKey, 0, 0, i);
        }
        else if(i == 1){
            runDiceLayer(nextCDI, 64, attesterLayers.TCIs[i - 1], attesterLayers.TCIs[i], SHA512_DIGEST_LENGTH, &x509, 0, 0, nonce, nonce_len, &previousPubKey, 0, 0, i);
        }
        else if(i == fileCount){
            runDiceLayer(nextCDI, 64, attesterLayers.TCIs[i - 1], FSD, SHA512_DIGEST_LENGTH, &x509, 1, 1, nonce, nonce_len, &previousPubKey, 1, 1, i);
        }
        else{
            runDiceLayer(nextCDI, 64, attesterLayers.TCIs[i - 1], attesterLayers.TCIs[i], SHA512_DIGEST_LENGTH, &x509, 0, 1, nonce, nonce_len, &previousPubKey, 0, 0, i);
        }
    }
    printer(data, "Attester_Measurement.txt", totalSize);

    return 0;
}
