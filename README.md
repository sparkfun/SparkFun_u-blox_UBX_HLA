
  # u-blox UBX Analyzer
  
A Logic2 High Level Analyzer for the u-blox UBX protocol

![Screen shot 1](./Screenshot_1.png)

![Screen shot 2](./Screenshot_2.png)

## v0.0.1

Proof of concept for Async Serial (UART) traffic: demonstrate that the HLA can successfully decode UBX frames when interleaved with NMEA (and/or RTCM) messages

Provide simple decoding of UBX frames: display the frame class, ID, length; extract UBX-NAV-PVT fields; validate the checksum

## Upgrade Path

Add support for I2C and SPI, compensating for the u-blox register layout and read transfers
