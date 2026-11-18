#!/bin/bash
# Provision the KTI server from OCI Cloud Shell (already authenticated): network, Always Free Ampere A1 instance
# (2 OCPU, 12 GB, 150 GB boot volume), cloud-init bootstrap. Idempotent by display name. Usage: bash provision.sh bootstrap.sh
set -euo pipefail
BOOT=${1:?bootstrap script}
C=${OCI_TENANCY:?}; R=${OCI_REGION:-us-chicago-1}
q() { oci "$@" --raw-output 2>/dev/null; }
VCN=$(q network vcn list -c $C --display-name kti-vcn --query 'data[0].id')
if [ -z "$VCN" ] || [ "$VCN" = null ]; then
  VCN=$(q network vcn create -c $C --cidr-blocks '["10.20.0.0/16"]' --display-name kti-vcn --dns-label kti --wait-for-state AVAILABLE --query data.id)
fi
IGW=$(q network internet-gateway list -c $C --vcn-id $VCN --query 'data[0].id')
if [ -z "$IGW" ] || [ "$IGW" = null ]; then
  IGW=$(q network internet-gateway create -c $C --vcn-id $VCN --is-enabled true --display-name kti-igw --wait-for-state AVAILABLE --query data.id)
fi
RT=$(q network vcn get --vcn-id $VCN --query 'data."default-route-table-id"')
oci network route-table update --rt-id $RT --force --route-rules "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$IGW\"}]" >/dev/null
SL=$(q network vcn get --vcn-id $VCN --query 'data."default-security-list-id"')
oci network security-list update --security-list-id $SL --force \
  --egress-security-rules '[{"destination":"0.0.0.0/0","protocol":"all","isStateless":false}]' \
  --ingress-security-rules '[{"source":"0.0.0.0/0","protocol":"6","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":22,"max":22}}},{"source":"0.0.0.0/0","protocol":"6","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":80,"max":80}}},{"source":"0.0.0.0/0","protocol":"6","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":443,"max":443}}},{"source":"0.0.0.0/0","protocol":"1","isStateless":false,"icmpOptions":{"type":3,"code":4}}]' >/dev/null
SUB=$(q network subnet list -c $C --vcn-id $VCN --display-name kti-public --query 'data[0].id')
if [ -z "$SUB" ] || [ "$SUB" = null ]; then
  SUB=$(q network subnet create -c $C --vcn-id $VCN --cidr-block 10.20.0.0/24 --display-name kti-public --dns-label pub --route-table-id $RT --security-list-ids "[\"$SL\"]" --wait-for-state AVAILABLE --query data.id)
fi
[ -f ~/.ssh/kti ] || ssh-keygen -q -t ed25519 -N '' -C kti-cloudshell -f ~/.ssh/kti
IMG=$(q compute image list -c $C --operating-system "Canonical Ubuntu" --operating-system-version "24.04" --shape VM.Standard.A1.Flex --sort-by TIMECREATED --sort-order DESC --query 'data[0].id')
echo "vcn=$VCN subnet=$SUB image=$IMG"
INST=$(q compute instance list -c $C --display-name kti-db --lifecycle-state RUNNING --query 'data[0].id')
if [ -z "$INST" ] || [ "$INST" = null ]; then
  for AD in $(q iam availability-domain list -c $C --query 'join(`" "`, data[].name)'); do
    echo "launching in $AD"
    if INST=$(oci compute instance launch -c $C --availability-domain "$AD" --shape VM.Standard.A1.Flex --shape-config '{"ocpus":2,"memoryInGBs":12}' \
        --image-id $IMG --subnet-id $SUB --assign-public-ip true --display-name kti-db --hostname-label kti-db \
        --ssh-authorized-keys-file ~/.ssh/kti.pub --user-data-file "$BOOT" --boot-volume-size-in-gbs 150 \
        --wait-for-state RUNNING --max-wait-seconds 900 --query data.id --raw-output); then break; fi
    echo "no capacity or error in $AD"; INST=
  done
fi
[ -n "$INST" ] || { echo "launch failed in every availability domain"; exit 2; }
IP=$(q compute instance list-vnics --instance-id $INST --query 'data[0]."public-ip"')
echo "instance=$INST ip=$IP host=${IP//./-}.sslip.io"
