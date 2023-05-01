# secure-pickle-files
The "pickle" package in python enables users to export almost any type of object containing data to an external file. This file can then be simply loaded into memory whenever the need for the object arises, as opposed to regenerating the object each time. The main application of this package is for objects which are computationally expensive to generate, such as machine learning models. This repo contains a python package which streamlines the process of ensuring the integrity of a pickle file by attaching a hash-based message authentication code (HMAC) with it.

## Usage

To use this package simply clone this repo and copy the 'securepickle' directory into whatever project you want to use it. Then with the line 'from securepickle import securedump, secureload' you can use the functions for yourself.
