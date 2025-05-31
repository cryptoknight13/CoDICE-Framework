#!/bin/bash

gcc ../CoDice_layers.c CoDice_test_endorser.c -lcrypto -g -o CoDice_test_endorser
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

echo "Compilation successful. Running the Endorser test..."
./CoDice_test_endorser Combined_Manifests/Manifest.diag

mv Endorser_Manifest.diag Endorsements/
mv Endorser_Public_Key.pem Endorsements/
mv Endorser_Certificate.pem Endorsements/
echo "Endorser test completed successfully. Output files moved to Endorserments directory."
if [ $? -ne 0 ]; then
    echo "Endorser test failed."
    exit 1
fi