#!/bin/bash
# Launch the two Always Free AMD micros (database + gateway, and SearXNG) in the kti-vcn public subnet.
# Usage: bash micro.sh   (idempotent by display name; tries each availability domain)
set -uo pipefail
C=$OCI_TENANCY
VCN=$(oci network vcn list -c $C --display-name kti-vcn --query 'data[0].id' --raw-output)
SUB=$(oci network subnet list -c $C --vcn-id $VCN --display-name kti-public --query 'data[0].id' --raw-output)
IMG=$(oci compute image list -c $C --operating-system "Canonical Ubuntu" --operating-system-version "24.04" --shape VM.Standard.E2.1.Micro --sort-by TIMECREATED --sort-order DESC --query 'data[0].id' --raw-output)
ADS=$(oci iam availability-domain list -c $C --query 'join(`" "`, data[].name)' --raw-output)
echo "image=$IMG"
for ROLE in db search; do
  NAME=kti-$ROLE-micro
  ID=$(oci compute instance list -c $C --display-name $NAME --query 'data[?"lifecycle-state"!=`TERMINATED`] | [0].id' --raw-output 2>/dev/null)
  if [[ "$ID" == ocid1.instance* ]]; then echo "$NAME exists $ID"; continue; fi
  for AD in $ADS; do
    out=$(oci compute instance launch --no-retry -c $C --availability-domain "$AD" --shape VM.Standard.E2.1.Micro --image-id $IMG --subnet-id $SUB \
      --assign-public-ip true --display-name $NAME --hostname-label kti-$ROLE --ssh-authorized-keys-file ~/.ssh/kti.pub \
      --user-data-file ~/kti/bootstrap-$ROLE.sh --boot-volume-size-in-gbs 50 --query data.id --raw-output 2>&1)
    if [[ "$out" == ocid1.instance* ]]; then echo "$NAME LAUNCHED in $AD: $out"; break; fi
    echo "$NAME $AD: $(echo "$out" | grep -o '"message": "[^"]*"' | head -1)"
  done
done
sleep 90
for ROLE in db search; do
  ID=$(oci compute instance list -c $C --display-name kti-$ROLE-micro --query 'data[?"lifecycle-state"!=`TERMINATED`] | [0].id' --raw-output)
  IP=$(oci compute instance list-vnics --instance-id $ID --query 'data[0]."public-ip"' --raw-output 2>/dev/null)
  echo "kti-$ROLE-micro $(oci compute instance get --instance-id $ID --query 'data."lifecycle-state"' --raw-output) ip=$IP host=${IP//./-}.sslip.io"
done
