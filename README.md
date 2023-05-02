# secure-pickle
The "pickle" package in python enables users to export almost any type of object containing data to an external file. This file can then be simply loaded into memory whenever the need for the object arises, as opposed to regenerating the object each time. The main application of this package is for objects which are computationally expensive to generate, such as machine learning models. This repo contains a python package which streamlines the process of ensuring the integrity of a pickle file by attaching a hash-based message authentication code (HMAC) with it.

## Usage

To use this package simply run the command 'pip3 install secure-pickle' and include the line 

`from securepickling.src.securepickle import securedump, secureload`

at the top of your file and then the two included functions will be callable by their name.

The package contains two functions which are based on the Python 'pickle' module: 

`securedump(obj, file, SECRETKEY)`

    desc: Writes bytedata of 'obj' and an HMAC generated with 'obj' and 'SECRETKEY' to 'file'

    params: obj - Any python object that you wish to write out to a pickle file
            file - A file object which must be in 'wb' mode
            SECRETKEY - A string or bytearray which must be at least 64 bytes to ensure security

    returns: nothing

`secureload(file, SECRETKEY)`

    desc: Loads bytedata from 'file' and verifies its integrity using the HMAC in the file and the bytedata and 'SECRETKEY'

    params: file - A file object which must be in 'rb' mode
            SECRETKEY - A string or bytearray which will be used to verify the HMAC

    returns: the object loaded from pickle file, assuming integrity check passes


## Links

https://pypi.org/project/secure-pickle/

https://github.com/Ethan-Dowalter/securepickling