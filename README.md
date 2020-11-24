# mfr

MFR - Memory Find and Replace is an open source memory manipulation tool. It is based on Frida framework. It can be used to manipulate memory of an Android or iOS application. 

Usage
---
python3 mfr.py app.package.name -f textToFind -r textToReplace


Important
---
If the new text (-r) is longer than the old text (-f) mfr may cause a buffer-overflow and may corrupt unrelated memory.


To find the package name of a process that is running on a USB connected device, you can use: 

      frida-ps -U
      
Installation
---
To install mfr you just need to clone it from git and run it:

      git clone https://github.com/mkaraoz/mfr.git
            
      python3 mfr.py app.package.name -f 'Market' -r test 'Frida'
            
Pre-requisites
---
To use mfr you need to have frida installed on host machine and mobile device. The easiest way to install frida on your python is using pip:

    pip3 install frida
    
More information on how to install Frida can be found [here](http://www.frida.re/docs/installation/)

For iOS, installation instructions can be found [here](http://www.frida.re/docs/ios/).

For Android, installation instructions can be found [here](http://www.frida.re/docs/android/). 

Thanks
---
Borrowed readme and part of the script from [Fridump](https://github.com/Nightbringer21/fridump).
