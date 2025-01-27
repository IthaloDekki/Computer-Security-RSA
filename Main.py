from RSA import RSA
import base64

# Exemplo de uso
rsa = RSA(bits=1024)
print("Primo p:", rsa.p)
print("Primo q:", rsa.q)
print("N (p * q):", rsa.n)

# Teste de cifração e decifração
mensagem = 42
cifrada = rsa.Encrypt(mensagem.to_bytes(4, "big"))
decifrada = rsa.Decrypt(cifrada)

print("\n--- Cifração e Decifração ---")
print("Mensagem original:", mensagem)
print("Mensagem cifrada:", cifrada)
print("Mensagem decifrada:", int.from_bytes(decifrada))

# Geração de chaves pública e privada
n = rsa.n
e = rsa.choicePublicExponent(rsa.p, rsa.q)  # Expoente público
d = rsa.choicePrivateExponent()  # Expoente privado

chave_publica = (n, e)
chave_privada = (n, d)

# Teste de assinatura e verificação
mensagem_clara = "Essa é uma mensagem de teste para assinatura RSA!"

# Gera a assinatura
assinatura = rsa.signature(chave_privada, mensagem_clara)
print("\n--- Assinatura ---")
print("Mensagem:", mensagem_clara)
print("Assinatura gerada (Base64):", assinatura.decode('utf-8'))

# Verifica a assinatura
validacao = rsa.verify_signature(chave_publica, mensagem_clara, assinatura)
print("\n--- Verificação ---")
if validacao:
    print("A assinatura é válida!")
else:
    print("A assinatura é inválida!")

# Teste de alteração de mensagem
mensagem_alterada = "Essa é uma mensagem alterada!"
validacao_alterada = rsa.verify_signature(chave_publica, mensagem_alterada, assinatura)
print("\n--- Teste com mensagem alterada ---")
if validacao_alterada:
    print("A assinatura ainda é válida (isso não deveria acontecer).")
else:
    print("A assinatura foi invalidada corretamente para a mensagem alterada.")
