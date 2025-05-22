# 3fa-auth-ufsc
Trabalho de implementacao de um sistema de autenticacao 3FA para disciliplina de seguranca da informacao UFSC

1. python3 -m venv env 
2. source env/bin/activate
3. pip3 install -r requirements.txt
4. python3 client.py / server.py / totp.py

-------

Caso estiver usando Windows:
1. python -m venv env

Abra 3 Prompts de comando, e em cada um digite:
2. env\Scripts\activate

Em um dos prompts:
3. pip install -r requirements.txt

Para cada um dos prompts, digite:
4. cd src
5. python3 client.py
    ou
   python3 server.py
    ou
   python3 totp.py
6. Exportar variavel de ambiente com token
export IPINFO_API_TOKEN=<valor>
    