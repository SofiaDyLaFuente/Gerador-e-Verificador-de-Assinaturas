# Referências: 
# https://blog.lsantos.dev/criptografia-assimetrica-com-rsa/
# https://cp-algorithms.com/algebra/primality_tests.html
# https://cp-algorithms.com/algebra/primality_tests.html
# https://docs.sympy.org/latest/modules/ntheory.html#sympy.ntheory.primetest.isprime
# https://www.geeksforgeeks.org/dsa/primality-test-set-3-miller-rabin/
# https://elc.github.io/python-security/chapters/07_Asymmetric_Encryption.html
# https://peps.python.org/pep-0506/
# https://github.com/tarcisio-marinho/RSA
# https://github.com/sympy/sympy/blob/d2be7bacd2604e98a642f74028e8f0d7d6084f78/sympy/ntheory/primetest.py#L499-L674
# https://docs.python.org/3/library/secrets.html
# https://inventwithpython.com/rabinMiller.py
# https://www.pycryptodome.org/en/latest/src/signature/pkcs1_v1_5.html
# https://cp-algorithms.com/algebra/module-inverse.html
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
# https://cp-algorithms.com/algebra/extended-euclid-algorithm.html
# https://nuitshell.blogspot.com/2014/07/algoritmo-estendido-de-euclides.html
# https://www.geeksforgeeks.org/computer-networks/rsa-algorithm-cryptography/
# https://dev.to/0x2633/the-flow-of-creating-digital-signature-and-verification-in-python-37ng

import secrets
import hashlib
import base64
import math


lista_primos = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 
    53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 
    109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167
]

# Teste de primalidade de Miller Rabin com 5 iterações 
def miller_rabin(numero):  # https://inventwithpython.com/rabinMiller.py
    if numero < 2:
        return False
    if numero == 2:
        return True
    if numero % 2 == 0:
        return False
        
    s = numero - 1
    t = 0
    while s % 2 == 0:
        s //= 2
        t += 1

    for _ in range(5):
        a = secrets.randbelow(numero - 3) + 2
        v = pow(a, s, numero)
        if v in (1, numero - 1):
            continue
            
        for i in range(t - 1):
            v = pow(v, 2, numero)
            if v == numero - 1:
                break
        else:
            return False
            
    return True

def gerar_primo(tamanho_bits):
    while True:
        # Gera um número aleatório com exatamente 'tamanho_bits' bits
        numero = secrets.randbits(tamanho_bits)
        
        # Garante que o bit mais significativo seja 1 e o número seja ímpar
        numero |= (1 << (tamanho_bits - 1)) | 1
        
        # Teste rápido com primos pequenos
        if any(numero % p == 0 for p in lista_primos if p < numero):
            continue
            
        # Teste de primalidade Miller-Rabin
        if miller_rabin(numero):
            return numero

def inverso_modular(a, m):
    # Algoritmo estendido de Euclides
    g, x, y = egcd(a, m)
    return x % m

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = egcd(b, a % b)
        g, x, y = g, y1, x1 - (a // b) * y1
        return (g, x, y)

def gerar_chave(tamanho_bits=1024):
    while True:
        # Gera cada primo com metade do valor desejado
        p = gerar_primo(tamanho_bits // 2)
        q = gerar_primo(tamanho_bits // 2)
        
        if p == q:
            continue
            
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        e = 65537
        if math.gcd(e, phi_n) != 1:
            continue
            
        try:
            d = inverso_modular(e, phi_n)
        except ValueError:
            continue
            
        # Chave pública: (e, n)
        # Chave privada: (d, n)
        chave_publica = (e, n)
        chave_privada = (d, n)
        return chave_publica, chave_privada


# def assinar_documento


# def verificar_assinatura