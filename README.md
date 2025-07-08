# Sistema de Assinatura e Verificação de Documentos Digitais (SAVDD)

> Trabalho para a disciplina de Segurança Computacional da Universidade de Brasília (UnB).

---

### Grupo 7
* Erick dos Santos Araújo;
* Luciana Alves Pereira;
* Sofia Dy La Fuente Monteiro.

---


**Pré-requisitos:**
* Python 3.x instalado.

**Passos de Instalação:**

1.  **Clone o repositório:**
    ```bash
    git clone https://github.com/SofiaDyLaFuente/Gerador-e-Verificador-de-Assinaturas.git
    cd Gerador-e-Verificador-de-Assinaturas
    ```

2.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure as variáveis de ambiente:**
    * Copie o arquivo de exemplo: `cp .env.example .env`
    * Preencha o arquivo `.env` com os valores necessários.

4.  **Execute o servidor:**
    ```bash
    python manage.py makemigrations
    python manage.py migrate
    python manage.py runserver
    ```

Após executar o último comando, o sistema estará disponível em `http://127.0.0.1:8000/`.
