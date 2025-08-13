function remote --description 'Connect to a remote server'
    echo "Checking if server is accessible..."
    
    # Test if DNS resolves (instant check)
    if nslookup amazon-ec2 >/dev/null 2>&1
        # DNS works, try SSH
        if ssh -o ConnectTimeout=2 -o BatchMode=yes amazon-ec2 exit 2>/dev/null
            echo "Server is running, connecting..."
        else  
            echo "Server stopped or starting, launching..."
            ./ec2-remote.sh --start
            if test $status -ne 0
                echo "Failed to start server"
                return 1
            end
        end
    else
        echo "No DNS entry - server definitely stopped, starting..."
        ./ec2-remote.sh --start
        if test $status -ne 0
            echo "Failed to start server"
            return 1
        end
    end
    
    # Connect to the server
    ssh amazon-ec2
end