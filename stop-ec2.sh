#!/bin/bash
INSTANCE_ID="i-08b680d7742cb2411"

echo "Stopping EC2 instance..."
aws ec2 stop-instances --instance-ids $INSTANCE_ID

echo "Waiting for instance to stop..."
for i in {1..30}; do
  STATE=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[*].Instances[*].State.Name' --output text)
  if [[ "$STATE" == "stopped" ]]; then
    echo "Instance stopped successfully"
    break
  fi
  echo "Attempt $i/30: Current state: $STATE"
  sleep 5
done

if [[ "$STATE" != "stopped" ]]; then
  echo "Warning: Instance may still be stopping (current state: $STATE)"
else
  echo "Done! EC2 instance is now stopped and not incurring compute charges."
fi