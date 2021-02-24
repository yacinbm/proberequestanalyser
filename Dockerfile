FROM nvcr.io/nvidia/l4t-base:r32.5.0
USER root

# Software Dependencies
RUN apt-get update
RUN apt-get install aircrack-ng

# Python Dependencies
RUN pip3 install tkinter scapy pandas netaddr

# Copy application
COPY . /opt/probe-request-analyzer
# Make executable
RUN chmod +x /opt/probe-request-analyzer/CLI/cli.py

# Set Container Entry Point
ENTRYPOINT [ "python3 /opt/probe-request-analyzer/CLI/cli.py" ]

# IMPORTANT NOTE:   The OS needs to have the correct
#                   wifi drivers and the kernel module must 
#                   be loaded with monitor mode. See documentation
#                   on how to install the drivers for more details.