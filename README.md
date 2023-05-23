# SAPWF

## Description
The code for paper "Website Fingerprinting with Packet Sampling: A More Realistic Approach in Real-world Networks".  

This program first applies packet sampling to the traffic which is captured and stored in pcap files.  
Then, it extracts the feature from the sampled data.

You need to indicate the path where the pcap files are storaged in data.cfg.  
You can also change the threshold and the sampling rate.
## Requirements
Cmake  
Mingw for Windows (or GCC for Linux)

## Instructions

1.  Create a build directory and enter the build directory.
 ```bash
    mkdir build
    cd build
  ```  

2.  Configure the project and generate a native build system.
  ```bash
    cmake ..
  ```  
3.  Compile and link the project.
  ```bash
     cmake --build .
  ```
4.  Copy the 4 dll files from the /dll directory and the data.cfg from the root directory into the /build directory.
5.  Run the program and the feature is saved in the name of '0_TLS_sampling.rate_32.TLS_20.csv'  (for example).
  ```bash
    feature.exe data.cfg
  ```



