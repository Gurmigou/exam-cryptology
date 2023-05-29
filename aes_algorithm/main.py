import aes_algorithm as aes

key = b'master key'
message = b'Hello Cryptology!'

encrypted_message = aes.encrypt(key, message)
print(encrypted_message)
print(aes.decrypt(key, encrypted_message))