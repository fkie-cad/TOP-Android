# TOP Case Studies

This repository contains case studies carried out in the context of the paper "Throw Oriented Programming on Android".

Each case study targets a particular important topic in binary security. For an overview, consider the following table.

| Topic        | Case Study                |
| :---: | :---: |
| Exploitation | [E^2VA Vulnerable Module](https://github.com/fkie-cad/TOP-Android/tree/main/case_study_exploitation)|
| Obfuscation  | [Self - Exploitation](https://github.com/fkie-cad/TOP-Android/tree/main/case_study_obfuscation)|

## Test Environment

Both case studies have been tested on a *Google Pixel 7* with build number [*TD1A.220804.031*](https://source.android.com/docs/setup/about/build-numbers), i.e. the device runs Android 13 revision 11.

Accordingly, all `.apk` files have been built for that test device. Also, `.vdex` files have been extracted from processes running on the test device.

## Exploitation via TOP

The case study on exploitation using TOP is based on [`PoCMterpModule`](https://github.com/fkie-cad/eeva/blob/main/damnvulnerableapp/app/src/main/java/com/damnvulnerableapp/vulnerable/modules/PoCMterpModule.java) in $E^2VA$. `PoCMterpModule` provides a *Write - What - Where* and *Read - What - Where* condition and thus fulfills the majority of assumptions made by TOP.

Goal of this case study is to show that chaining TOP gadgets is possible. Therefore, all gadgets chained are *NOP gadgets*, i.e. of the form `throw v0`. More complex computations like setting up a socket connection should be possible, because $E^2VA$ uses network `Socket`s. However, finding a target method with reachable, suitable gadgets is an involved and tedious process.

In the following, major components of the exploitation case study are listed.

| Component | Description |
| :---: | :---: |
| [PoCExploit.py](https://github.com/fkie-cad/TOP-Android/blob/main/case_study_exploitation/PoCExploit.py) | *Proof of Concept* exploit script that requires the base address of `libart.so` and a copy of `libart.so` for symbol parsing. Then, the script tracks down `base.vdex` and patches the method [`NetworkEndPoint::isConnected`](https://github.com/fkie-cad/eeva/blob/main/damnvulnerableapp/app/src/main/java/com/damnvulnerableapp/networking/communication/client/NetworkEndPoint.java#L159) to trigger execution of a TOP chain. |
| [base.apk](https://github.com/fkie-cad/TOP-Android/blob/main/case_study_exploitation/base.apk) | Application file of $E^2VA$ used in the case study. |
| [base.vdex](https://github.com/fkie-cad/TOP-Android/blob/main/case_study_exploitation/base.vdex) | `.vdex` file used for finding gadgets, exception types and patch offsets. Essentially, this file is what is patched at runtime to trigger a TOP chain. |

The patches applied to `base.vdex` at runtime have been computed with [*Topper*](https://github.com/fkie-cad/Topper), a tool designed to generate patches for exception handler injection assuming a *Write - What - Where* condition.

## TOP - based Obfuscation by Self - Exploitation

Another use - case, and a more practical one than *exploitation*, is obfuscating the behaviour of an application using TOP. Hence, this is verified in a case study of its own.

The goal is to abuse the fact that all assumptions of TOP will be fulfilled, if the target application is attacker - controlled. A software type, for which TOP - based obfuscation is especially interesting, is *malware*.

Composition and structure of the case study can be seen below.

| Component | Description |
| :---: | :---: |
| [PoCTOPObfuscation](https://github.com/fkie-cad/TOP-Android/tree/main/case_study_obfuscation/code/PoCTOPObfuscation) | Android Studio project of the "malicious" app. The app simply xor - decrypts a `char[]` using a secret key to obtain a new text to display via a `TextView`. Because `nterp` does not need bytecode to be executable, the actual instructions are hidden in a randomly generated data table. **Do not open this project in Android Studio**. `table.h` is **very** large, which may crash Android Studio or the web browser used to inspect the file. |
| [app-release.apk](https://github.com/fkie-cad/TOP-Android/blob/main/case_study_obfuscation/app-release.apk) | Signed application file that can be installed on a **test** device. This is a copy of the `.apk` file generated from the `PoCTOPObfuscation` project. |
| [generate_table.py](https://github.com/fkie-cad/TOP-Android/blob/main/case_study_obfuscation/generate_table.py) | Script, which has been used to generate the table in `table.h`. It simply prepares tuples of offset - instructions pairs to hide in the random table. The offsets are used in a `packed-switch` dispatcher. Hidden instructions are chained so that they decrypt a string to display. |

Obviously, knowing about *TOP* eases reverse engineering, because the `packed-switch-payload` functions as a gadget lookup. However, notice that gadgets are stored in a data section, meaning that gadgets may also be hidden in structured data etc. Furthermore, as TOP gadgets are fully controllable by an attacker and are stored in writable memory, the bytecode program could be implemented in a polymorphic manner, or with further randomization.
