# 3fa-auth-ufsc
Trabalho de implementacao de um sistema de autenticacao 3FA para disciliplina de seguranca da informacao UFSC

Instalacao: 
1. python3 -m venv env 
2. source env/bin/activate 
2.1 Caso estiver usando Windows:  env\Scripts\activate
3. pip3 install -r requirements.txt
4. python3 client.py / server.py


Execucao:
1. Abra 2 sessoes de terminal no diretorio base do projeto (uma pode ser a sessao de instalacao aberta anteriormente)
2. Em cada uma ative o ambiente virtual (paco 2 da instalacao)
3. Execute os seguintes comando para iniciar o servidor: 
3.1 export IPINFO_API_TOKEN=<api-token>
3.2 python3 src/server.py
4. Execute em seguinda o seguinte comando para iniciar o cliente: python3 src/client.py
5. Execute a aplicacao pelo menu no terminal.