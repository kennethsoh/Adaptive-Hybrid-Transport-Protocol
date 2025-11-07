# Adaptive-Hybrid-Transport-Protocol
Adaptive Hybrid Transport Protocol for Games

_NUS CS3103 Assignment 4 (AY25/26 S1)_

## Instructions to Run
### Pre-requisites
1) Ensure the Latest Version of Python is installed
2) Download the relevant modules before running (Use pip to install E.g pip3 install <Module Name>)
    - aioquic
    - pycryptodome
    - matplotlib

### Instructions to Run
1) Ensure all Pre-Requisites are Installed
2) Download the 3 Files, GameNetAPI.py, sender.py and receiver.py into the same folder
3) Go to the Folder in your 2 terminal windows, and run the files in the following order
    - python receiver.py
    - python sender.py

### Metrics
Once the Sender is done Running, it will show Connection Closed. Verify that you see this "Connection Closed" in the Receiver Application as well,
then stop the programme by using "Ctrl-C" or its equivalent. The Experiment Metrics will be shown on both the Sender & Receiver Applications

You can observe the Latency Plot through the generated "receiver_latency_plot.png" file.
