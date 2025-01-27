from RSA import RSA


# Exemplo de uso
rsa = RSA(bits=1024)
print("Primo p:", rsa.p)
print("Primo q:", rsa.q)
print("N (p * q):", rsa.n)

mensagem = 42
cifrada = rsa.Encrypt(mensagem.to_bytes(4,"big"))
decifrada = rsa.Decrypt(cifrada)

print("Mensagem original:", mensagem)
print("Mensagem cifrada:", cifrada)
print("Mensagem decifrada:", int.from_bytes(decifrada))