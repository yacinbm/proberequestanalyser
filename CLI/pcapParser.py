from source.captureEngine import CaptureEngine
import os

directory = os.fsencode("./data/log")
engine = CaptureEngine(None)

for file in os.listdir(directory):
    filename = os.fsdecode(file)
    if filename.endswith(".pcap"): 
        engine.readCapFile("./data/log/"+filename)
        continue
    else:
        continue

print(len(engine.capturedPackets))