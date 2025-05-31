#!/bin/bash
# This script sets up the environment for the Endorser service.
echo "Setting up AFM Manifest..."
python3 ../../unified-cddl-generator.py ../../AFM/
python3 ../../diag_generator.py ../../AFM/afm.json
mv diag_auto_gen.diag AFM_Manifest/
mv ../../AFM/auto-gen.cddl AFM_Manifest/
diag2cbor.rb AFM_Manifest/diag_auto_gen.diag > AFM_Manifest/AFM_Manifest.cbor
output=$(cddl AFM_Manifest/auto-gen.cddl validate AFM_Manifest/AFM_Manifest.cbor)
if [ -z "$output" ]; then
    echo "AFM validation successful."
else
    echo "AFM validation failed: $output"
    exit 1
fi
echo "Adding AFM Manifest to Combined Manifest"
cat AFM_Manifest/diag_auto_gen.diag > Combined_Manifests/Manifest.diag
echo "," >> Combined_Manifests/Manifest.diag

echo "Setting up BMC and PCH Manifests..."
python3 ../../unified-cddl-generator.py ../../BMC_PCH/
python3 ../../diag_generator.py ../../BMC_PCH/bmc_pch.json
mv diag_auto_gen.diag BMC_PCH_Manifest/
mv ../../BMC_PCH/auto-gen.cddl BMC_PCH_Manifest/
diag2cbor.rb BMC_PCH_Manifest/diag_auto_gen.diag > BMC_PCH_Manifest/BMC_PCH_Manifest.cbor
output=$(cddl BMC_PCH_Manifest/auto-gen.cddl validate BMC_PCH_Manifest/BMC_PCH_Manifest.cbor)
if [ -z "$output" ]; then
    echo "BMC/PCH validation successful."
else
    echo "BMC/PCH validation failed: $output"
    exit 1
fi
echo "Adding BMC and PCH Manifests to Combined Manifest"
cat BMC_PCH_Manifest/diag_auto_gen.diag >> Combined_Manifests/Manifest.diag
echo "," >> Combined_Manifests/Manifest.diag
cat BMC_PCH_Manifest/diag_auto_gen.diag >> Combined_Manifests/Manifest.diag

echo "Combined Manifest created successfully."
echo "Endorser Corim manifest is ready for use."

exit 0