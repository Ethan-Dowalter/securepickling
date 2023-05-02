import pickle
import hmac
import hashlib
import os

def securedump(obj, file, SECRETKEY):
    # Make sure file object is in correct mode
    if (not ('b' in file.mode and 'w' in file.mode)):
        file.close()
        raise("Please make sure the file object passed to 'securedump' is in 'wb' mode!")
    # Make sure SECRETKEY is longer than minimum size of 32 bytes to ensure security
    if (len(SECRETKEY) < 64):
        file.close()
        raise("Please use a key that is at least 64 bytes to ensure security!")
    # Get byte data of object
    bytedata = pickle.dumps(obj)
    # Generate HMAC with object byte data and SECRETKEY using sha3
    myhmac = hmac.new(SECRETKEY, bytedata, hashlib.sha3_512)
    # Write the object byte data to file
    file.write(bytedata)
    # Append the 64-byte HMAC to file
    file.write(myhmac.digest())
    # Close file
    file.close()

def secureload(file, SECRETKEY):
    # Make sure file object is in correct mode
    if (not ('b' in file.mode and 'r' in file.mode)):
        file.close()
        raise("Please make sure the file object passed to 'secureload' is in 'rb' mode!")
    # Get the length of the file in bytes to separate the 64-byte HMAC on the end
    file.seek(0, os.SEEK_END)
    filesize = file.tell()
    # Error out if file is not longer than the 64-byte HMAC
    if (filesize < 65):
        file.close()
        raise("Uh oh! Provided file was too small and the integrity of the pickle file could not be verified!")
    # Move the cursor back to the start
    file.seek(0)
    # Get the byte data by only reading to the last 64 bytes of the file
    bytedata = file.read(filesize - 64)
    # Generate the HMAC for verification using the retrieved byte data and given SECRETKEY
    verificationHMAC = hmac.new(SECRETKEY, bytedata, hashlib.sha3_512).digest()
    # Read the last 64 bytes for the HMAC in the file
    fileHMAC = file.read()
    # Assume failure pattern
    if (fileHMAC != verificationHMAC):
        # Close file
        file.close()
        # Throw error because HMACs did not match
        raise("Uh oh! Integrity of pickle file could not be verified!")
    else:
        # Reset file cursor
        file.seek(0)
        # Read the file normally, luckily according to the docs: "Bytes past the pickled representation of the object are ignored."
        # So it's able to read the file even with the 64-byte HMAC appended to the end completely fine
        data = pickle.load(file)
        # Close file
        file.close()
        # Return safely
        return data