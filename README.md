# Defeating Encryption By Using Unicorn Engine - Workshop

## Intro

Software Reverse-Engineering (SRE) is often considered black magic, but with the right tools and knowledge, its processes can be significantly accelerated. Unicorn Engine is a powerful framework that allows you to execute code platform-independently, which can greatly enhance your SRE skills.

Applications, binaries, and frameworks often contain complex functionalities like encryption and decryption methods that are hidden from the user. Reverse-engineering these can be difficult and time-consuming, especially when they involve non-standard, proprietary or non-documented cryptographic functions. This is where Unicorn Engine comes in. It enables us to execute code dynamically without the need for the proper environment or hardware. By emulating the execution, we can analyse and understand the underlying operations, making the reverse-engineering process more effective.

With Unicorn Engine, you can dissect and manipulate code in a controlled environment. Whether you are dealing with malware analysis, software debugging, or vulnerability research, Unicorn Engine is an awesome tool in your reverse-engineering toolkit.

This workshop will focus on reverse-engineering one or more binaries with Ghidra. Participants will identify various encryption or obfuscation functions and write code for Unicorn Engine in Python to utilise these functions without ever executing the binary.

No special knowledge is required, but familiarity with Python, Ghidra, and x86/x64 assembly would be beneficial. The training will introduce Unicorn Engine to the audience and explain it in depth.


## Pre-reqs

Install JDK: [Eclipse Temurin](https://adoptium.net/en-GB/temurin/releases/)  
Download the latest Ghidra: [Releases](https://github.com/NationalSecurityAgency/ghidra/releases) - Requires JDK  

## Github Codespaces

Instead of using a virtual machine, it's possible to run the whole environment in Github Codespaces (in your browser). Follow the steps below:
1. Login to your Github account
2. Fork this repository
3. Click the green <> Code button
4. Select Codespaces
5. Click on "Create codespaces on main"

You still need to run Ghidra on your computer though.  

Disclaimer: Do not forget to stop your instance after you are done.