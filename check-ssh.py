import paramiko  # Importa a biblioteca para lidar com conexões SSH
import socket  # Usado para manipulação de conexões de rede
import sys  # Manipula argumentos de linha de comando

# Lista de portas comuns para o serviço SSH
known_ssh_ports = [22, 2222, 2022, 8022, 2200]

# Função que tenta se conectar a um servidor SSH e pegar a versão
def get_ssh_version(host, port):
    try:
        # Cria um socket de rede para comunicação
        sock = socket.socket()
        sock.settimeout(5)  # Define um tempo limite para a conexão
        
        # Tenta se conectar ao host no porto SSH fornecido
        sock.connect((host, port))
        
        # Recebe dados (banner) do servidor SSH, que inclui a versão
        banner = sock.recv(1024).decode().strip()
        print(f"[+] Porta {port} aberta - SSH Banner: {banner}")  # Exibe o banner de versão SSH
        
        sock.close()  # Fecha a conexão
        return banner  # Retorna o banner para possível análise
    except Exception as e:
        print(f"[-] Porta {port} fechada ou não acessível: {e}")
        return None

# Função que verifica se a versão SSH possui vulnerabilidades conhecidas
def check_ssh_vulnerabilities(banner):
    # Base expandida de vulnerabilidades conhecidas no SSH e variantes
    vulnerabilities = {
        # Vulnerabilidades OpenSSH
        'OpenSSH_8.4': 'Possivelmente vulnerável a CVE-2021-41617 (Problema de permissões de arquivo)',
        'OpenSSH_8.2': 'Possivelmente vulnerável a CVE-2020-14145 (Problema de bypass de autenticação)',
        'OpenSSH_7.9': 'Possivelmente vulnerável a CVE-2018-15473 (Falha de enumeração de usuarios)',
        'OpenSSH_7.4': 'Possivelmente vulnerável a CVE-2016-10012 (Execução de código remoto)',
        'OpenSSH_6.6.1': 'Possivelmente vulnerável a CVE-2015-5600 (Ataque de força bruta no teclado interativo)',
        'OpenSSH_7.2': 'Possivelmente vulnerável a CVE-2016-0777 e CVE-2016-0778 (Vazamento de memória e chave privada)',
        'OpenSSH_5.8': 'Possivelmente vulnerável a CVE-2011-5000 (Bypass de autenticação), CVE-2011-4327 (Negação de serviço), CVE-2011-3268 (Enumeração de usuários), CVE-2010-4478 (Facilitação de força bruta)',
        'OpenSSH_5.3': 'Possivelmente vulnerável a CVE-2018-15473 (Falha de enumeração de usuarios)',

        # Vulnerabilidades libssh
        'libssh-0.8.1': 'Possivelmente vulnerável a CVE-2018-10933 (Autenticação de bypass)',
        'libssh-0.7.0': 'Possivelmente vulnerável a CVE-2016-0739 (Buffer overflow)',
        
        # Vulnerabilidades Dropbear SSH
        'Dropbear_2016.74': 'Possivelmente vulnerável a CVE-2016-7408 (Buffer overflow em tratamento de nomes)',
        'Dropbear_2012.55': 'Possivelmente vulnerável a CVE-2012-0920 (Problemas de segurança no SCP)',

        # Vulnerabilidades outras
        'Cisco-SSH_1.25': 'Possivelmente vulnerável a CVE-2003-1564 (Ataque de negação de serviço)',
        'Sun_SSH_1.1.2': 'Possivelmente vulnerável a CVE-2007-2243 (Problema de autenticação no gerenciamento de chave pública)',
    }
    
    # Verifica se o banner contém uma versão vulnerável conhecida
    for version, vulnerability in vulnerabilities.items():
        if version in banner:
            print(f"[!] Alerta: {version} - {vulnerability}")
            return vulnerability
    print("[+] Nenhuma vulnerabilidade conhecida detectada.")
    return None

# Função principal que coleta a URL e tenta identificar vulnerabilidades em maltiplas portas
def main():
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <host>")
        sys.exit(1)
    
    host = sys.argv[1]  # O host é o primeiro argumento da linha de comando
    
    # Itera sobre todas as portas comuns de SSH
    for port in known_ssh_ports:
        print(f"\n[*] Verificando a porta {port} no host {host}...")
        banner = get_ssh_version(host, port)
        
        if banner:
            # Verifica vulnerabilidades associadas ao banner SSH
            check_ssh_vulnerabilities(banner)

# Verifica se o script está sendo executado diretamente
if __name__ == '__main__':
    main()
#by Geovane da costa Oliveira
