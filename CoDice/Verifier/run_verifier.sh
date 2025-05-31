#!/bin/bash

# This script runs the Verifier test for CoDice.
echo "Running Verifier test..."
gcc ../CoDice_layers.c CoDice_test_verifier.c -lcrypto -g -o CoDice_test_verifier
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

mv Endorser_Public_Key.pem Endorsements/
mv Endorser_Certificate.pem Endorsements/
mv Endorser_Manifest.diag Endorsements/
mv Attester_Public_Key.pem Evidence/
mv Attester_Cert.pem Evidence/
mv Attester_Measurement.txt Evidence/
echo "Compilation successful. Running the Verifier test..."

./CoDice_test_verifier Endorsements/Endorser_Manifest.diag Evidence/Attester_Cert.pem Evidence/Attester_Public_Key.pem Evidence/Attester_Measurement.txt Endorsements/Endorser_Certificate.pem Endorsements/Endorser_Public_Key.pem 
exit 0
