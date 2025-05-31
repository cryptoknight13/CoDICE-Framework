#!/bin/bash

echo "Running Attester test..."
gcc ../CoDice_layers.c CoDice_test_attester.c -lcrypto -g -o CoDice_test_attester
if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi
./CoDice_test_attester AFM_Evidence/AFM_Layer_One.diag BMC_PCH_Evidence/BMC_PCH_Layer_Two.diag BMC_PCH_Evidence/BMC_PCH_Layer_Three.diag
mv Attester_Measurement.txt Evidence/
mv Attester_Public_Key.pem Evidence/
mv Attester_Cert.pem Evidence/
echo "Attester test completed successfully. Output files moved to Evidence directory."
