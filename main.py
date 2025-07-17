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
import os
#from docx import Document
from sys import byteorder


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

def serializar_chave_publica(chave_publica):
    e, n = chave_publica
    conteudo = f"{e}:{n}".encode('utf-8')  # Melhor usar : como separador
    base64_chave = base64.b64encode(conteudo).decode('ascii')
    
    return (
        "-----BEGIN PUBLIC KEY-----\n" +
        '\n'.join(base64_chave[i:i+64] for i in range(0, len(base64_chave), 64)) +
        "\n-----END PUBLIC KEY-----"
    )

def serializar_chave_privada(chave_privada):
    d, n = chave_privada
    conteudo = f"{d}:{n}".encode('utf-8')
    base64_chave = base64.b64encode(conteudo).decode('ascii')
    
    return (
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        '\n'.join(base64_chave[i:i+64] for i in range(0, len(base64_chave), 64)) +
        "\n-----END RSA PRIVATE KEY-----"
    )

def desserializar_chave_publica(pem):
    # Define os cabeçalhos
    header_start = "-----BEGIN PUBLIC KEY-----"
    header_end = "-----END PUBLIC KEY-----"
    
    # Encontra as posições dos cabeçalhos
    start_idx = pem.find(header_start)
    end_idx = pem.find(header_end)
    
    # Calcula o início do conteúdo (após o primeiro cabeçalho)
    content_start = start_idx + len(header_start)
    
    # Extrai o conteúdo entre os cabeçalhos
    conteudo_base64 = pem[content_start:end_idx].strip()
    
    # Remove espaços em branco e quebras de linha
    conteudo_base64 = ''.join(conteudo_base64.split())
    
    try:
        # Decodifica o conteúdo
        conteudo = base64.b64decode(conteudo_base64).decode('utf-8')
        e_str, n_str = conteudo.split(':')
        return (int(e_str), int(n_str))
    except Exception as e:
        raise ValueError(f"Erro ao desserializar chave pública: {str(e)}")

def desserializar_chave_privada(pem):
    # Define os cabeçalhos
    header_start = "-----BEGIN RSA PRIVATE KEY-----"
    header_end = "-----END RSA PRIVATE KEY-----"
    
    # Encontra as posições dos cabeçalhos
    start_idx = pem.find(header_start)
    end_idx = pem.find(header_end)
    
    # Calcula o início do conteúdo (após o primeiro cabeçalho)
    content_start = start_idx + len(header_start)
    
    # Extrai o conteúdo entre os cabeçalhos
    conteudo_base64 = pem[content_start:end_idx].strip()
    
    # Remove espaços em branco e quebras de linha
    conteudo_base64 = ''.join(conteudo_base64.split())
    
    try:
        # Decodifica o conteúdo
        conteudo = base64.b64decode(conteudo_base64).decode('utf-8')
        d_str, n_str = conteudo.split(':')
        return (int(d_str), int(n_str))
    except Exception as e:
        raise ValueError(f"Erro ao desserializar chave privada: {str(e)}")

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


def gerar_chave(tamanho_bits):
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
# Abertura dos arquivos
def leitura_arquivo(caminho):
    extensao = os.path.splitext(caminho)[1].lower()

    if extensao in [".txt", ".pdf"]:
        with open(caminho, "rb") as arq:
            return arq.read()

    elif extensao == ".docx":
        doc = Document(caminho)
        texto = "\n".join(par.text for par in doc.paragraphs)
        return texto.encode("utf-8")


# Cálculo do hash SHA3-256
def calculo_hash_sha3(conteudo):
    hash_sha3 = hashlib.sha3_256(conteudo)
    resumo_mensagem = hash_sha3.digest()
    print("Hash: ", resumo_mensagem.hex())
    return resumo_mensagem


# Geração da máscara MGF1
def gerar_mascara(seed_bytes, comprimento_saida):
    resultado = b""
    cont = 0
    while len(resultado) < comprimento_saida:
        cont_bytes = cont.to_bytes(4, "big")
        hash_encaminhado = hashlib.sha3_256(seed_bytes + cont_bytes).digest()
        resultado += hash_encaminhado
        cont += 1
    return resultado[:comprimento_saida]


# Padding com PSS
def padding_pss(hash_msg_original: bytes, tamanho_total: int, tamanho_sal=32):
    h_len = 32  # Tamanho do hash SHA3-256

    sal_aleatorio = os.urandom(tamanho_sal) # Valor aleatório
    
    # Mensagem com prefixo 0x00 * 8 + hash original + salt
    mensagem_para_hash = b'\x00' * 8 + hash_msg_original + sal_aleatorio
    
    # Hash SHA-3
    hash_final = hashlib.sha3_256(mensagem_para_hash).digest()
    
    # Cálculo do espaço de padding
    tamanho_padding_zeros = tamanho_total - tamanho_sal - h_len - 2
    
    bloco_dados = b'\x00' * tamanho_padding_zeros + b'\x01' + sal_aleatorio
    
    # Gera máscara e aplica XOR
    mascara_dados = gerar_mascara(hash_final, len(bloco_dados))
    dados_ocultos = bytes(b1 ^ b2 for b1, b2 in zip(bloco_dados, mascara_dados))
    
    # Concatena os dados com hash e sufixo final
    bloco_final = dados_ocultos + hash_final + b'\xbc'
    
    tamanho_obtido = len(bloco_final)
    if tamanho_obtido < tamanho_total:
        padding_extra = b'\x00' * (tamanho_total - tamanho_obtido)
        bloco_final = padding_extra + bloco_final   
    return bloco_final


# Assinatura
def assinar_bloco_padded(bloco_padded: bytes, chave_privada: tuple):
    d, n = chave_privada
    bloco_inteiro = int.from_bytes(bloco_padded, "big")    
    assinatura_inteira = pow(bloco_inteiro, d, n)
    tamanho_bytes = (n.bit_length() + 7) // 8
    return assinatura_inteira.to_bytes(tamanho_bytes, "big")


# Base
def assinatura_para_base64(assinatura_bytes: bytes):
    return base64.b64encode(assinatura_bytes).decode("utf-8")


# def verificar_assinatura
def verificar_assinatura(conteudo_arquivo: bytes, assinatura_bytes: bytes, chave_publica: tuple) -> bool:
    e, n = chave_publica
    em_len = (n.bit_length() + 7) // 8  # Tamanho do módulo em bytes
    tamanho_sal = 32
    tamanho_hash = 32
    
    try:
        # Calcular hash do conteúdo
        hash_calculado = calculo_hash_sha3(conteudo_arquivo)
        
        # Verificar tamanho da assinatura
        if len(assinatura_bytes) != em_len:
            print(f"Tamanho incorreto: esperado {em_len}, recebido {len(assinatura_bytes)}")
            return False
            
        # Converter para inteiro e decifrar
        assinatura_int = int.from_bytes(assinatura_bytes, "big")
        bloco_int = pow(assinatura_int, e, n)
        bloco_decifrado = bloco_int.to_bytes(em_len, "big")
        
        # Verificar trailer
        if bloco_decifrado[-1] != 0xBC:  # 0xBC = 188
            print("Assinatura inválida. Não é um arquivo PSS")
            return False
            
        # Extrair componentes
        hash_final_extraido = bloco_decifrado[em_len - tamanho_hash - 1 : -1]
        dados_ocultos = bloco_decifrado[: em_len - tamanho_hash - 1]
        
        # Gerar máscara e decodificar DB
        mascara = gerar_mascara(hash_final_extraido, len(dados_ocultos))
        bloco_original = bytes(b ^ m for b, m in zip(dados_ocultos, mascara))
        
        # Extrair salt - método robusto
        try:
            # O salt está nos últimos 'tamanho_sal' bytes
            # O byte antes do salt deve ser 0x01
            if bloco_original[-tamanho_sal - 1] != 0x01:
                print("Separador 0x01 não encontrado na posição esperada")
                return False
                
            salt_extraido = bloco_original[-tamanho_sal:]
        except IndexError:
            print("Tamanho do bloco insuficiente para extrair salt")
            return False
        
        # Recalcular hash
        mensagem_para_hash = b'\x00' * 8 + hash_calculado + salt_extraido
        novo_hash_final = hashlib.sha3_256(mensagem_para_hash).digest()
        
        # Comparar hashes
        if novo_hash_final == hash_final_extraido:
            print("Assinatura verificada!")
            return True
        else:
            print("Hash final diferente!")
            print(f"Esperado: {hash_final_extraido.hex()}")
            print(f"Calculado: {novo_hash_final.hex()}")
            return False
            
    except Exception as e:
        print(f"Erro na verificação: {str(e)}")
        return False
    

def main():
    while True:
        print("----------------------------------------")
        print("| Gerador e Verificador de Assinaturas |")
        print("----------------------------------------")
        print("\nEscolha uma opção:")
        print("1 - Gerar chaves")
        print("2 - Assinar mensagem")
        print("3 - Verificar assinatura")
        print("4 - Sair")
        
        escolha = input("Opção: ")

        if escolha == "1":
            tamanho_bits = int(input("Escolha o tamanho da chave: (Digite 1024 ou 2048) "))
            chave_publica, chave_privada = gerar_chave(tamanho_bits)

            chave_publica_pem = serializar_chave_publica(chave_publica)
            chave_privada_pem = serializar_chave_privada(chave_privada)

            print(f"\nChave privada:\n {chave_privada_pem}")
            print(f"\nChave pública:\n {chave_publica_pem}")

            with open('chave_publica.pem', 'w') as f:
                f.write(chave_publica_pem)

            with open('chave_privada.pem', 'w') as f:
                f.write(chave_privada_pem)

        elif escolha == "2":
            arquivo = input("Digite o caminho para o documento que deseja assinar: ")
            
            if os.path.exists(arquivo):
                with open(arquivo, "rb") as msg:
                    documento = msg.read()

            caminho_chave_privada = input("Digite o caminho para a chave privada: ")
            
            with open(caminho_chave_privada, 'r') as f:
                chave = f.read()

            chave_privada = desserializar_chave_privada(chave)
        
            hash_msg = calculo_hash_sha3(documento)
            tamanho_bytes = (chave_privada[1].bit_length() + 7) // 8
            bloco_padded = padding_pss(hash_msg, tamanho_bytes)
            
            # Gerar assinatura
            assinatura_bytes = assinar_bloco_padded(bloco_padded, chave_privada)
            assinatura_b64 = base64.b64encode(assinatura_bytes).decode("utf-8")
            with open('assinatura.sig', 'w') as f:
                f.write(assinatura_b64)
            
            print("Mensagem assinada com sucesso!")

        elif escolha == "3":
            
            arquivo = input("Digite o caminho do arquivo do documento original: ")
            if os.path.exists(arquivo):
                with open(arquivo, "rb") as msg:
                    documento = msg.read()

            assinatura = input("Digite o caminho do arquivo da assinatura: ")
            if os.path.exists(assinatura):
                with open(assinatura, "rb") as msg:
                    assinatura_b64 = msg.read()
                    assinatura_bytes = base64.b64decode(assinatura_b64)

            chave_publica_pem = input("Digite o caminho do arquivo da chave pública: ")
            if os.path.exists(chave_publica_pem):
                with open(chave_publica_pem, "r") as f:
                    chave = f.read()

            chave_publica = desserializar_chave_publica(chave)

            valido = verificar_assinatura(
                documento,
                assinatura_bytes,
                chave_publica
            )
            
            print(f"Assinatura válida? {valido}")

        elif escolha == "4":
            print("Saindo...")
            break

        else:
            print("Opção inválida! Tente novamente.")

if __name__ == "__main__":
    main()
