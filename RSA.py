import random
import hashlib
from os import urandom
from math import ceil
from hashlib import sha1, sha3_256
from operator import xor


class RSA:
    def _init_(self, bits=1024):
        self.bits = bits
        self.p = self.generate_primes()
        self.q = self.generate_primes()
        self.n = self.p * self.q

    # Função Fn que multiplica p-1 e q-1
    def functionFn(self, p, q):
        return (p - 1) * (q - 1)

    # Verifica se o número passado como argumento é um número primo usando Miller-Rabin
    def test_miller_rabin(self, n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    # Geração de um número primo de tamanho especificado
    def generate_primes(self):
        while True:
            maybe_prime = random.getrandbits(self.bits) | (1 << (self.bits - 1)) | 1  # Garante que o número tem 'bits' de tamanho
            if self.test_miller_rabin(maybe_prime):
                return maybe_prime

    # Escolhe um expoente público aleatório que seja coprimo com a função Fn e seja primo
    def choicePublicExponent(self, p, q):
        Fn = self.functionFn(p, q)
        publicExpoent = 3
        while publicExpoent < Fn:
            if Fn % publicExpoent != 0 and self.test_miller_rabin(publicExpoent):
                return publicExpoent
            publicExpoent += 2
        raise ValueError("Não foi possível encontrar um expoente público válido.")

    # Calcula o expoente privado com base nas regras estabelecidas (inverso modular)
    def choicePrivateExponent(self):
        publicExpoent = self.choicePublicExponent(self.p, self.q)
        Fn = self.functionFn(self.p, self.q)
        privateExpoent = self.inverso_modular(publicExpoent, Fn)
        return privateExpoent

    # Função para calcular o inverso modular
    def inverso_modular(self, a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1
    # Aplica uma máscara em uma mensagem. Com um valor pseudo-aleátorio passado como parâmetro e o tamanho desejado
    def mask(self,message,seed,size):
        #Inicia um vetor vazio
        IV = b''
        # Itera no range de 0 até a divisão inteira do tamanho desejado por 20
        for i in range(ceil(size/20)):
            #Converte o valor decimal para um número binário de 4 bytes no formato big-endian
            value = i.to_bytes(4,"big")
            #Soma ao vetor vazio um hash da soma da seed com o valor convertido para 20 bytes
            IV += sha1(seed + value).digest()
        return bytes(map(xor,message,bytes(len(message))+IV[:size]))
    def OAEP_encode(self,message):
        #Calcula o tamanho de bytes necessário
        k = (self.bits + 7)//8
        #Calcula o tamanho da mensagem em bytes
        message_len = len(message)
        #Tamanho do hash que será usado na criptografia. No caso, como é o SHA1 o hash gerado tem 20 bytes
        hash = 20
        #Hash fixo e padrão que tem 20 bytes usado para preenchimento
        lable_hash = b"\xda9\xa3\xee^kK\r2U\xbf\xef\x95\x18\x90\xaf\xd8\x07\t"
        #Construção de uma string de zeros para preenchimento.
        padding_string = b"\x00" * (k - message_len - 2 * hash - 2)
        # Construção do bloco com o lable, o preenchimento de 0's, um separador e a mensagem
        data = lable_hash + padding_string + b'\x01' + message
        #Criação de um hash de 20 bytes usando a função urandom
        seed = urandom(hash)
        #Construção da máscara do bloco que contém a mensagem
        masked_block = self.mask(data, seed, k - hash - 1)
        #Construção da máscara da seed
        masked_seed = self.mask(seed,masked_block,hash)
        #Retorna um separador inicial, o bloco com a máscara e a semente também com a máscara
        return b'\x00' + masked_seed + masked_block
    def OAEP_decode(self,message):
        # Calcula o tamanho de bytes necessário
        k = (self.bits + 7) // 8
        # Tamanho do hash que será usado na criptografia. No caso, como é o SHA1 o hash gerado tem 20 bytes
        hash = 20
        #Separa a mensagem em três partes: a primeira vairável é só o byte de inicialização que
        #não será utilizado, a segunda e a seed com a mascára e a terceira é o bloco que contém
        # a mensagem com a mascára
        _, masked_seed, masked_block = message[:1], message[1:1 + hash], message[1 + hash:]
        #masked_seed foi obtida usando a função mask com a seed e o masked_data_block, se usarmos
        #a função entre masked_seed e masked_block obtemos a seed
        seed = self.mask(masked_seed, masked_block, hash)
        #Da mesma forma, o masked_block foi obtido usando a mask entre o block e a seed. Fazendo o
        #o processo inverso obtemos o block que contém a mensagem
        block = self.mask(masked_block, seed, k - hash - 1)
        #Separamos o preenchimento da mensagem utilizando o split
        _, message = block.split(b'\x01')
        return message
    # Realiza a encriptação da mensagem
    def Encrypt(self, plaintext):
        #Usa o OAEP na mensagem
        OAEP_message=self.OAEP_encode(plaintext)
        #Escolhe um expoente público com base em dois números primos
        publicExpoent = self.choicePublicExponent(self.p, self.q)
        #Utiliza o RSA para encriptar a mensagem
        ciphertext = pow(int.from_bytes(OAEP_message), publicExpoent, self.n)
        return ciphertext

    # Realiza a decriptação da mensagem
    def Decrypt(self, ciphertext):
        k = (self.bits + 7) // 8
        #Calcula o expoente privado
        privateExpoent = self.choicePrivateExponent()
        #Transforma a mensagem cifrada para um OAEP
        OAEP_message = pow(ciphertext, privateExpoent, self.n)
        #Obtém o texto plano
        plaintext = self.OAEP_decode(OAEP_message.to_bytes(k,"big"))
        return plaintext