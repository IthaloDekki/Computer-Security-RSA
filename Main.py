from RSA import RSA

mensagem = int(input("Digite a mensagem que deseja ser codificada: "))

rsa = RSA(bits=1024)
print("Primo p:", rsa.p)
print("Primo q:", rsa.q)
print("N (p * q):", rsa.n)

# Teste de cifração e decifração
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


#Gerar e verificar com uma mensagem longa
mensagem_longa = "A" * 500  # Mensagem com 500 caracteres 'A'
assinatura_longa = rsa.signature(chave_privada, mensagem_longa)
validacao_longa = rsa.verify_signature(chave_publica, mensagem_longa, assinatura_longa)
print("\n--- Teste com Mensagem Longa ---")
print("Mensagem Longa (primeiros 30 caracteres):", mensagem_longa[:30] + "...")
print("Assinatura (Base64):", assinatura_longa.decode('utf-8'))
print("A assinatura é válida para a mensagem longa!" if validacao_longa else "A assinatura é inválida para a mensagem longa!")


#Gerar e verificar com uma mensagem curta
mensagem_curta = "Oi"
assinatura_curta = rsa.signature(chave_privada, mensagem_curta)
validacao_curta = rsa.verify_signature(chave_publica, mensagem_curta, assinatura_curta)
print("\n--- Teste com Mensagem Curta ---")
print("Mensagem Curta:", mensagem_curta)
print("Assinatura (Base64):", assinatura_curta.decode('utf-8'))
print("A assinatura é válida para a mensagem curta!" if validacao_curta else "A assinatura é inválida para a mensagem curta!")