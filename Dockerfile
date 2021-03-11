FROM python:3.6.9-slim
USER root

# Software Dependencies
RUN apt-get update
RUN apt-get install -y wireless-tools tcpdump

# Python Dependencies
# numpy>1.19.4 crashes on the jetson for some reason
RUN pip3 install numpy==1.19.4 pandas scapy netaddr

# Copy application
COPY . /opt/probe-request-analyzer

# Add to path
ENV PYTHONPATH "$PYTHONPATH:/opt/probe-request-analyzer/"

# Make executable
RUN chmod +x /opt/probe-request-analyzer/DockerApp/probe_request_capture.py

# Set Container Entry Point
ENTRYPOINT [ "python3", "/opt/probe-request-analyzer/DockerApp/probe_request_capture.py" ]

# IMPORTANT NOTE:   The OS needs to have the correct
#                   wifi drivers and the kernel module must 
#                   be loaded with monitor mode. See documentation
#                   on how to install the drivers for more details.