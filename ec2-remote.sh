#!/bin/bash

# Check for required environment variables
if [[ -z "$AMAZON_REMOTE_INSTANCE_ID" ]]; then
    echo "Error: AMAZON_REMOTE_INSTANCE_ID environment variable is not set"
    echo "Example: export AMAZON_REMOTE_INSTANCE_ID=i-08b680d7742cb2411"
    exit 1
fi

if [[ -z "$AMAZON_REMOTE_REGION" ]]; then
    echo "Error: AMAZON_REMOTE_REGION environment variable is not set"
    echo "Example: export AMAZON_REMOTE_REGION=us-east-2"
    exit 1
fi

INSTANCE_ID="$AMAZON_REMOTE_INSTANCE_ID"
REGION="$AMAZON_REMOTE_REGION"

# Function to show usage
show_usage() {
    echo "Usage: $0 [--start|--stop|--status]"
    echo ""
    echo "Options:"
    echo "  --start    Start the EC2 instance and update DNS"
    echo "  --stop     Stop the EC2 instance"
    echo "  --status   Check the current status of the instance"
    echo ""
    echo "Environment variables required:"
    echo "  AMAZON_REMOTE_INSTANCE_ID    The EC2 instance ID"
    echo "  AMAZON_REMOTE_REGION         The AWS region (e.g., us-east-2)"
    exit 1
}

# Function to start instance
start_instance() {
    echo "Starting EC2 instance $INSTANCE_ID..."
    aws ec2 start-instances --instance-ids $INSTANCE_ID --region $REGION

    echo "Waiting for instance to get public IP..."
    for i in {1..30}; do
        NEW_IP=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --region $REGION --query 'Reservations[*].Instances[*].PublicIpAddress' --output text)
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
    sudo dns_edit update amazon-ec2 $NEW_IP

    echo "Done! You can now: ssh remote"
}

# Function to stop instance
stop_instance() {
    echo "Stopping EC2 instance $INSTANCE_ID..."
    aws ec2 stop-instances --instance-ids $INSTANCE_ID --region $REGION

    echo "Waiting for instance to stop..."
    for i in {1..30}; do
        STATE=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --region $REGION --query 'Reservations[*].Instances[*].State.Name' --output text)
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
}

# Function to check instance status
status_instance() {
    STATE=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --region $REGION --query 'Reservations[*].Instances[*].State.Name' --output text 2>/dev/null)
    if [[ -n "$STATE" ]]; then
        echo "$STATE"
    else
        echo "unknown"
    fi
}

# Parse command line arguments
case "$1" in
    --start)
        start_instance
        ;;
    --stop)
        stop_instance
        ;;
    --status)
        status_instance
        ;;
    *)
        show_usage
        ;;
esac