function remote --description 'Connect to a remote server'
    echo "Checking server status..."
    
    # Check AWS instance status
    set status (./ec2-remote.sh --status)
    
    if test "$status" = "running"
        echo "Server is running, connecting..."
    else
        echo "Server is $status, starting EC2 instance..."
        ./ec2-remote.sh --start
        if test $status -ne 0
            echo "Failed to start server"
            return 1
        end
    end
    
    # Connect to the server
    ssh amazon-ec2
end