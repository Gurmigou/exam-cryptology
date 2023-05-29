import nyberg_rueppel as nr

text = "Hello Cryptology!"

nybergRueppel = nr.NybergRueppelAlgorithm()

key_private = nybergRueppel.generate_keys()
key_public = key_private[:-1]

signature_by_private_key = nybergRueppel.sign(text, key_private)

print("Text:", text)
print("Key public:", key_public)

print("Signature by private key:", signature_by_private_key)
print("Verification old-message:", nybergRueppel.verify(text, signature_by_private_key, key_public))


new_text = "New text message"
print("New message: ", new_text)
print("Verification new-message:", nybergRueppel.verify(new_text, signature_by_private_key, key_public))
