# CFFHashes #

----------

CFFHashes is a simple extension to CFF Explorer ( [http://www.ntcore.com/exsuite.php](http://www.ntcore.com/exsuite.php) ) by Daniel Pistelli. This extension provides CRC32, MD5, SHA1 and SHA256 hashes of various parts of PE file. You can also perform a custom hash on any area of the file.

A 'Check VirusTotal' button is provided to quickly check and see if the calculated SHA256 has been reported previously. 

## Usage ##

When you launch CFF Explorer, a new 'Hashes' item will be displayed. You can quickly view hashes of common file areas, or simply specify your own file offset and length  (in hex) to calculate the hashes of a custom range in the file.

![](https://raw.githubusercontent.com/bfosterjr/CFFHashes/master/cffhashes.png)