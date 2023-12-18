# SAPWF
## Description
The code for paper "Website Fingerprinting with Packet Sampling: A More Realistic Approach in Real-world Networks".

This program first applies packet sampling to the traffic which is captured and stored in pcap files.
Then, it extracts the feature from the sampled data.

You need to indicate the path where the pcap files are storaged in data.cfg.
You can also change the threshold and the sampling rate.

## Requirement
Windows system

## Instructions

1. Change the parameters in the file data.cfg
2. Get into fhe folder where the files are located and open a windows terminal 
3.  Run the program and the feature is saved in the file names '0_TLS_sampling.rate_32.TLS_20.csv'  (for example).
  ```bash
    feature.exe 
  ```


