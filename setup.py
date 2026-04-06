import os
import subprocess
import sys
import shutil

def check_nmap():
    print("🔍 Verificando motor Nmap...")
    nmap_path = shutil.which("nmap")
    common_windows_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]
    
    if nmap_path:
        print(f"✅ Nmap encontrado em: {nmap_path}")
        return True
    
    for path in common_windows_paths:
        if os.path.exists(path):
            print(f"✅ Nmap encontrado em: {path}")
            return True
            
    print("❌ ERRO: Nmap não encontrado. Instale em https://nmap.org/download.html")
    return False

def install_dependencies():
    print("📦 Instalando bibliotecas Python...")
    libs = ["streamlit", "python-nmap", "requests", "psutil", "python-dotenv", "shodan", "scapy"]
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *libs])
        print("✅ Bibliotecas instaladas com sucesso.")
    except Exception as e:
        print(f"❌ Erro ao instalar dependências: {e}")

def setup_env():
    if not os.path.exists(".env"):
        print("📝 Criando arquivo .env de configuração...")
        content = (
            "SHODAN_API_KEY=\n"
            "ABUSEIPDB_API_KEY=\n"
            "VIRUSTOTAL_API_KEY=\n"
            "NVD_API_KEY=\n"
        )
        with open(".env", "w") as f:
            f.write(content)
        print("⚠️  Arquivo .env criado! Insira suas chaves de API antes de iniciar.")
    else:
        print("✅ Arquivo .env já existe.")

if __name__ == "__main__":
    print("=== CÉREBRO v3.8 - INSTALADOR DE AMBIENTE ===\n")
    install_dependencies()
    setup_env()
    check_nmap()
    print("\n🚀 Configuração concluída. Para iniciar, use: streamlit run main.py")