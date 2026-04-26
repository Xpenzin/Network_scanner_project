import socket
import sys

#NOTES:
#connect_ex error code meanings
# 0 = success, port is OPEN
# 111  = connection refused, port is CLOSED
# 110  = connection timed out, port is FILTERED (firewall blocking it)
# 113  = no route to host, target unreachable

# terminal input (if no input is provided)
try:
    if len(sys.argv) == 2:
        print("Did not provide any value (will add instructions alter on)")
        print("\nInput format:")
        print("target ip addr (or range)")
        print("target port specification (type '=' if you want range in between, example: =25-130)")
# terminal input (target info)
    elif len(sys.argv) == 3:
        HOST = sys.argv[1]
        PORT = sys.argv[2]
    
except IndexError:
    print("probably provided more input than needed. Try again")

# NUMBER OF OPEN PORTS
total_ports = 0

# PORT VALUES (scan ports between x and y)
if "-" in sys.argv[2]:
    port_list = PORT.split('-')
    
    first_val = int(port_list[0])
    last_val = int(port_list[1])
    
    #tuple of port number (in int value)
    ports = []

    for port in range(first_val, last_val+1):
        ports.append(port)


# CIDR SCAN (network scan and host descovery)
if "/24" in str(HOST):
    host_ip_list = HOST.split('.')
    
    #tuple of IP addresses
    ip_addrs = []
    
    # Creating list of all possible hosts in the provided network
    for num in range(1, 255):
        ip_addrs.append(f"{host_ip_list[0]}.{host_ip_list[1]}.{host_ip_list[2]}.{num}")


# NETWORK PORT ENUMERATION 
scann = socket.socket()
try:
    # Scanning network based on port range and host discovery in the specified network
    if "/24" in str(HOST) and "-" in sys.argv[2]:
        for addr in ip_addrs:
            for p in ports:
                status = scann.connect_ex((addr, p))
                if status == 0:
                    total_ports += total_ports + 1
                    print(f"Host found with open port!: {addr}")
                    print(f"\nPort '{p}' is OPEN")
                    print(f"Total open ports: {total_ports}")

    # Scanning network based on a specific port    
    elif "/24" in str(HOST) and "-" not in sys.argv[2]:
        for addr in ip_addrs:
            status = scann.connect_ex((addr, int(ports)))

        #Port state description and host discovery in the specified network
            if status == 0:
                print(f"\nPort '{str(PORT)}' is OPEN")
    
            elif status == 110:
                print(f"\nPort '{str(PORT)}' is filtered (errorno type -> timed out)")
    
            elif status == 111:
                print(f"\nPort '{str(PORT)}' is closed (errorno type -> CONNECTION REFUSED)")
    
            elif status == 113:
                print(f"\nPort '{str(PORT)}' has no route (errorno type -> target unreachable")
    
except Exception as error:
    print(f"Error has occured in 'NETWORK PORT ENUMERATION':")
    print(f"\n{error}")
    
finally:
    scann.close()


# If input isn't CIDR notation or network scan (individual host scan)
if "/" not in str(HOST):
    scann = socket.socket()
    
    try:
        # Scanning based on port range
        if "-" in sys.argv[2]:
            for port in ports:
                status = scann.connect_ex((HOST, int(port)))
                if status == 0:
                    total_ports += total_ports + 1
                    print(f"\nPort '{str(port)}' is OPEN")
                    print(f"Total open ports: {total_ports}")
                
        
        elif "-" not in sys.argv[2]:
            status = scann.connect_ex((HOST, int(PORT)))
                
            if status == 0:
                print(f"\nPort '{str(PORT)}' is OPEN")
                total_ports += total_ports + 1
    
            elif status == 110:
                print(f"\nPort '{str(PORT)}' is filtered (errorno type -> timed out)")
    
            elif status == 111:
                print(f"\nPort '{str(PORT)}' is closed (errorno type -> CONNECTION REFUSED)")
    
            elif status == 113:
                print(f"\nPort '{str(PORT)}' has no route (errorno type -> target unreachable")
    
    
    except Exception as error:
        print("ERROR IN CIDR NOTATION SECTION")
        print(f"\n{error}")
    
    finally:
        scann.close()

if total_ports == 0:
    print("No ports were found")