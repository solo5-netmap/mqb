# MirageOS Unikernel based MQTT broker
This is prototype implementation of an MQTT broker written for MirageOS Unikernel.

## Usage
1. Modify IP setting in `./config.ml` so that your unikernel can run on your network environment
2. Compile this program and execute it as usual.  
(eg. `mirage configure -t ukvm; make; sudo ./ukvm-bin --net=tap0 ./mqb.ukvm` for ukvm)
