# STS EA07_DA07
A Java based EA07 and DA07 according to the Standard Transfer Specification (STS).

## Installation & Prerequisits
This program was written and tested with Java 17. Consider compiling and running with the same JDK version.<br>
Also, make sure your installed Java can be accessible via your terminal.

## First Run
**Step 1.** Clone this repo to your local computer.<br>
**Step 2.** From your terminal, navigate to the local project's folder.<br>
**Step 3.** Run `javac Program.java` and `java Program`. Run both commands sequentially.<br>

## Notes
This program focuses on demonstrating both encryption and decryption using the 07 algos with predefined `Decoder_Key`, `Data_Block` (as a binary string) and `Data_Class` (as a binary string).<br>
These values can be tweaked as desired.

## Further Reading
For futher info on all aspects of the STS application level, check out *Let’s demystify that 20-digit utility token*:<br>
[Part 1](https://mwangi-patrick.medium.com/lets-demystify-that-20-digit-utility-token-part-1-74c85eebbac4)<br>
[Part 2](https://medium.com/codex/lets-demystify-that-20-digit-utility-token-part-2-64ca45f4b88b)<br>
[Part 3](https://medium.com/codex/lets-demystify-that-20-digit-utility-token-part-3-d05002dbdf71)
