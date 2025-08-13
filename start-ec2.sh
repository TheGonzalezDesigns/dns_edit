#!/bin/bash
INSTANCE_ID="i-08b680d7742cb2411"

echo "Starting EC2 instance..."
aws ec2 start-instances --instance-ids $INSTANCE_ID

echo "Waiting for instance to get public IP..."
for i in {1..30}; do
  NEW_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[*].Instances[*].PublicIpAddress' --output text)
  if [[ -n "$NEW_IP" && "$NEW_IP" != "None" ]]; then
    echo "Got IP: $NEW_IP"
    break
  fi
  echo "Attempt $i/30: Still waiting..."
  sleep 5
done

if [[ -z "$NEW_IP" || "$NEW_IP" == "None" ]]; then
  echo "Failed to get IP address"
  exit 1
fi

echo "Updating DNS entry amazon-ec2 -> $NEW_IP"
dns_edit update amazon-ec2 $NEW_IP

echo "Done! You can now: ssh remote"