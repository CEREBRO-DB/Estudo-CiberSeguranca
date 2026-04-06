import streamlit as st
import os
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp

# Importação dos Agentes do diretório /agentes
from agentes.orion import Orion
from agentes.vektor import Vektor
from agentes.phantom import Phantom
from agentes.watchdog import Watchdog
from agentes.aegis import Aegis
from agentes.brain_sync import BrainSync

# Carregar variáveis de ambiente (.env)
load_dotenv()

# --- 1. CONFIGURAÇÃO DA PÁGINA ---
st.set_page_config(
    page_title="CÉREBRO v3.8.5 - Full Access", 
    layout="wide", 
    page_icon="🧠"
)

# --- 2. INICIALIZAÇÃO DOS MOTORES ---
if 'motores_iniciados' not in st.session_state:
    st.session_state.orion = Orion(os.getenv("SHODAN_API_KEY"), os.getenv("ABUSEIPDB_API_KEY"))
    st.session_state.vektor = Vektor(os.getenv("VIRUSTOTAL_API_KEY"))
    st.session_state.phantom = Phantom()
    st.session_state.watchdog = Watchdog()
    st.session_state.aegis = Aegis()
    st.session_state.sync = BrainSync()
    st.session_state.motores_iniciados = True

# --- 3. GESTÃO DE MEMÓRIA ---
if 'dados_scan' not in st.session_state:
    st.session_state.dados_scan = None

# --- 4. BARRA LATERAL ---
with st.sidebar:
    st.title("🧠 CÉREBRO v3.8.5")
    st.write(f"📅 **Data:** {datetime.now().strftime('%d/%m/%Y')}")
    st.markdown("---")
    
    if st.button("🔄 SINCRONIZAR ECOSSISTEMA"):
        with st.spinner("Atualizando bases globais..."):
            logs = st.session_state.sync.sincronizar_tudo(
                st.session_state.orion, 
                st.session_state.vektor, 
                st.session_state.aegis
            )
            for log in logs:
                st.toast(log)
            st.success("Inteligência Sincronizada!")

    st.markdown("---")
    
    modo = st.radio("Módulos Operacionais:", [
        "🏠 Orion (Rede Local)", 
        "🌍 Orion (Rede Externa)", 
        "💣 Vektor (Exploits & Arsenal)", 
        "🛡️ Aegis (Plano de Defesa)", 
        "👁 Phantom (Social)",
        "⚙️ Intelligence Hub"
    ])
    
    if st.button("🗑 Limpar Memória do Scan"):
        st.session_state.dados_scan = None
        st.rerun()

# --- 5. LÓGICA DOS MÓDULOS ---

# Módulo: ORION (REDE LOCAL)
if modo == "🏠 Orion (Rede Local)":
    st.header("🏠 Orion: Auditoria e Reconhecimento")
    
    col1, col2 = st.columns(2)
    with col1:
        st.subheader("🛰️ Discovery")
        faixa_auto = st.session_state.orion.obter_rede_automatica()
        if st.button("🔍 Listar Dispositivos"):
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=faixa_auto), timeout=2, verbose=0)[0]
            devs = [{"IP": r[1].psrc, "MAC": r[1].hwsrc} for r in result]
            st.table(pd.DataFrame(devs))

    with col2:
        st.subheader("🕵️ Watchdog")
        if st.button("📡 Capturar Tráfego (5s)"):
            with st.spinner("Sniffing ativo..."):
                st.dataframe(pd.DataFrame(st.session_state.watchdog.capturar(timeout=5)))

    st.divider()
    
    st.subheader("🔎 Scan Agressivo (TCP/UDP + Scripts NSE)")
    faixa_manual = st.text_input("Alvo (IP ou Faixa):", value=faixa_auto)
    intensidade = st.select_slider("Nível:", options=["Normal (Rápido)", "Médio (Vulnerabilidades)", "Máximo (Agressivo ao Extremo)"])
    
    if st.button("🚀 Iniciar Varredura"):
        barra = st.progress(0)
        res = st.session_state.orion.scan_rede_local_stealth(faixa_manual, intensidade)
        st.session_state.dados_scan = res
        barra.progress(100)
        
        if isinstance(res, dict) and "erro" not in res:
            for ip, srvs in res.items():
                with st.expander(f"🖥️ Host: {ip}"):
                    if isinstance(srvs, list):
                        for s in srvs:
                            if isinstance(s, dict):
                                porta = s.get('porta', 'N/A')
                                produto = s.get('produto', 'Desconhecido')
                                versao = s.get('versao', '')
                                st.write(f"**Porta {porta}**: {produto} {versao}")
                                
                                vulns = s.get('vulnerabilidades')
                                if vulns:
                                    st.error(f"Falhas: {list(vulns.keys())}")
                            else:
                                st.write(f"ℹ️ Dado bruto: {s}")
                    else:
                        st.info(f"Status do Host: {srvs}")
        else:
            st.error(f"Erro no Scan: {res.get('erro') if isinstance(res, dict) else res}")

# Módulo: ORION (REDE EXTERNA / OSINT)
elif modo == "🌍 Orion (Rede Externa)":
    st.header("🌍 Orion: Inteligência Externa & OSINT")
    st.info("Busca passiva em bases globais para reconhecimento de alvos externos.")
    
    col_input, col_btn = st.columns([3, 1])
    with col_input:
        target_externo = st.text_input("Insira o IP ou Domínio Externo:", placeholder="ex: 177.73.55.105")
    with col_btn:
        st.write(" ") 
        btn_rastrear = st.button("🚀 Rastrear Alvo", use_container_width=True)

    if btn_rastrear:
        if target_externo:
            with st.spinner("Realizando análise profunda de inteligência..."):
                # 1. Coleta de Dados via BrainSync
                geo = st.session_state.sync.rastrear_ip_externo(target_externo)
                sho = st.session_state.sync.consultar_shodan(target_externo)
                rep = st.session_state.sync.verificar_reputacao(target_externo)
                ame = st.session_state.sync.analisar_ameaca_rede(target_externo)
                
                # --- PAINEL: LOCALIZAÇÃO ---
                if geo:
                    st.subheader("📍 Localização e Provedor")
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Localização", geo['local'])
                    m2.metric("ISP", geo['isp'])
                    m3.metric("Coordenadas", geo['lat_lon'])
                    
                    try:
                        lat, lon = map(float, geo['lat_lon'].split(','))
                        df_mapa = pd.DataFrame({'lat': [lat], 'lon': [lon]})
                        st.map(df_mapa)
                    except:
                        st.warning("Falha ao renderizar mapa.")
                
                st.divider()

                # --- PAINEL: REPUTAÇÃO (ABUSEIPDB) ---
                st.subheader("🛡️ Reputação e Nível de Risco")
                if rep and "erro" not in rep:
                    r1, r2, r3 = st.columns(3)
                    score = rep['score_abuso']
                    status_cor = "normal" if score < 20 else "inverse"
                    r1.metric("Confiança de Abuso", f"{score}%", f"{rep['total_reportes']} reportes", delta_color=status_cor)
                    r2.write(f"**Uso Detectado:** {rep['tipo_uso']}")
                    r3.write(f"**Domínio:** {rep.get('dominio', 'N/A')}")
                else:
                    st.info("ℹ️ Dados de reputação não disponíveis para este alvo.")

                # --- PAINEL: INFRAESTRUTURA (PROXY/VPN) ---
                if ame:
                    st.write("---")
                    a1, a2, a3 = st.columns(3)
                    a1.warning(f"🎭 **VPN/Proxy:** {ame['e_proxy_vpn']}")
                    a2.info(f"☁️ **DataCenter:** {ame['e_data_center']}")
                    a3.success(f"📱 **Móvel:** {ame['e_movel']}")

                st.divider()
                
                # --- PAINEL: SHODAN ---
                st.subheader("🔍 Inteligência de Portas (Shodan)")
                if "erro" not in sho:
                    st.success(f"✅ Dados obtidos para: {target_externo}")
                    c_sho1, c_sho2 = st.columns(2)
                    with c_sho1:
                        st.write("**🖥️ OS Detectado:**", sho['os'])
                        st.write("**🔌 Portas Abertas:**", sho['portas'] if sho['portas'] else "Nenhuma porta pública detectada")
                    with c_sho2:
                        st.write("**📛 Hostnames:**", sho['hostnames'] if sho['hostnames'] else "Nenhum hostname listado")
                    
                    if sho['vulnerabilidades']:
                        st.warning("⚠️ **Vulnerabilidades Críticas (CVEs):**")
                        st.write(sho['vulnerabilidades'])
                else:
                    st.info(f"ℹ️ Shodan: {sho['erro']}")
        else:
            st.warning("Por favor, insira um IP ou Domínio válido.")

# Módulo: VEKTOR (ATAQUE)
elif modo == "💣 Vektor (Exploits & Arsenal)":
    st.header("💣 Vektor: Arsenal de Exploração")
    if st.session_state.dados_scan:
        if st.button("🔥 Gerar Plano de Ataque"):
            arsenal = st.session_state.vektor.buscar_exploits_locais(st.session_state.dados_scan)
            st.text_area("Lista de Exploração", arsenal, height=500)
    else:
        st.warning("⚠️ Faça um scan no Orion primeiro.")

# Módulo: AEGIS (DEFESA)
elif modo == "🛡️ Aegis (Plano de Defesa)":
    st.header("🛡️ Aegis: Inteligência de Remediação")
    if st.session_state.dados_scan:
        if st.button("🛠️ Gerar Protocolo de Correção"):
            plano = st.session_state.aegis.gerar_guia_correcao(st.session_state.dados_scan)
            st.text_area("Guia de Defesa", plano, height=500)
            st.download_button("📥 Baixar TXT", plano, "remediacao.txt")
    else:
        st.warning("⚠️ Realize um scan no Orion primeiro.")

# Módulo: PHANTOM (SOCIAL)
elif modo == "👁 Phantom (Social)":
    st.header("👁 Engenharia Social")
    texto = st.text_area("Análise de Texto:")
    if st.button("🔍 Analisar"):
        st.json(st.session_state.phantom.analisar_social(texto))

# Módulo: INTELLIGENCE HUB
elif modo == "⚙️ Intelligence Hub":
    st.header("⚙️ Central de Inteligência")
    st.write(st.session_state.sync.carregar_inteligencia_local())