import streamlit as st
import os
import time
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp

from agentes.orion import Orion
from agentes.vektor import Vektor
from agentes.phantom import Phantom
from agentes.watchdog import Watchdog
from agentes.aegis import Aegis
from agentes.brain_sync import BrainSync

load_dotenv()

st.set_page_config(
    page_title="CÉREBRO v3.8.5 - Full Access",
    layout="wide",
    page_icon="🧠"
)

if 'motores_iniciados' not in st.session_state:
    st.session_state.orion = Orion(os.getenv("SHODAN_API_KEY"), os.getenv("ABUSEIPDB_API_KEY"))
    st.session_state.vektor = Vektor(os.getenv("VIRUSTOTAL_API_KEY"))
    st.session_state.phantom = Phantom()
    st.session_state.watchdog = Watchdog()
    st.session_state.aegis = Aegis()
    st.session_state.sync = BrainSync()
    st.session_state.motores_iniciados = True

if 'dados_scan' not in st.session_state:
    st.session_state.dados_scan = None

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

# --- MÓDULO: ORION LOCAL ---
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

    faixa_auto = st.session_state.orion.obter_rede_automatica()
    faixa_input = st.text_input(
        "Alvo (IP ou Faixa):",
        placeholder=f"Ex: 192.168.1.105 ou {faixa_auto}",
        key="faixa_input"
    )
    faixa_manual = faixa_input.strip() if faixa_input.strip() else faixa_auto
    st.caption(f"🎯 Alvo que será escaneado: `{faixa_manual}`")

    intensidade = st.select_slider("Nível:", options=[
        "Normal (Rápido)", "Médio (Vulnerabilidades)", "Máximo (Agressivo ao Extremo)"
    ])

    tempo_estimado = {
        "Normal (Rápido)": 30,
        "Médio (Vulnerabilidades)": 120,
        "Máximo (Agressivo ao Extremo)": 300
    }

    if st.button("🚀 Iniciar Varredura"):
        orion = st.session_state.orion
        thread = orion.scan_rede_local_stealth(faixa_manual, intensidade)

        if thread is None:
            st.error(f"Erro ao iniciar scan: {orion.obter_erro()}")
        else:
            status_box = st.empty()
            barra = st.progress(0)
            info_box = st.empty()

            etapas = [
                (0.10, "🔍 Descobrindo hosts na rede..."),
                (0.30, "📡 Verificando portas abertas..."),
                (0.55, "🔎 Identificando serviços e versões..."),
                (0.75, "⚡ Executando scripts NSE..."),
                (0.90, "📊 Processando resultados..."),
            ]

            total_estimado = tempo_estimado[intensidade]
            inicio = time.time()
            etapa_idx = 0

            while thread.is_alive():
                elapsed = time.time() - inicio
                progresso_tempo = min(elapsed / total_estimado, 0.95)

                while etapa_idx < len(etapas) - 1 and progresso_tempo >= etapas[etapa_idx + 1][0]:
                    etapa_idx += 1

                pct = int(progresso_tempo * 100)
                label = etapas[etapa_idx][1]

                barra.progress(progresso_tempo)
                status_box.markdown(f"**{label}**")
                info_box.caption(f"⏱️ {int(elapsed)}s decorridos | ~{max(0, total_estimado - int(elapsed))}s restantes | {pct}% concluído")
                time.sleep(0.5)

            barra.progress(1.0)
            status_box.markdown("**✅ Varredura concluída!**")
            info_box.caption(f"⏱️ Tempo total: {int(time.time() - inicio)}s | 100% concluído")

            if orion.obter_erro():
                st.error(f"Erro no Scan: {orion.obter_erro()}")
            else:
                res = orion.obter_resultado()
                st.session_state.dados_scan = res

                if res:
                    for ip, srvs in res.items():
                        with st.expander(f"🖥️ Host: {ip} | OS: {srvs.get('os','?')} | Estado: {srvs.get('estado','?')}"):
                            col_a, col_b = st.columns(2)
                            with col_a:
                                st.write(f"**MAC:** {srvs.get('mac', 'N/A')}")
                                st.write(f"**Hostname:** {srvs.get('hostname', 'N/A')}")
                                st.write(f"**Local:** {srvs.get('local', 'N/A')}")
                                st.write(f"**ISP:** {srvs.get('isp', 'N/A')}")
                            with col_b:
                                servicos = srvs.get('servicos', [])
                                if servicos:
                                    st.write("**Portas Abertas:**")
                                    for s in servicos:
                                        versao = f" — `{s.get('versao')}`" if s.get('versao') else ""
                                        st.write(f"• `{s['porta']}/{s['protocolo']}` {s.get('servico','')}{versao}")
                                else:
                                    st.info("Nenhuma porta detectada.")
                else:
                    st.warning("Nenhum resultado encontrado.")

# --- MÓDULO: ORION EXTERNO ---
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
                geo = st.session_state.sync.rastrear_ip_externo(target_externo)
                sho = st.session_state.sync.consultar_shodan(target_externo)
                rep = st.session_state.sync.verificar_reputacao(target_externo)
                ame = st.session_state.sync.analisar_ameaca_rede(target_externo)

                if geo:
                    st.subheader("📍 Localização e Provedor")
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Localização", geo['local'])
                    m2.metric("ISP", geo['isp'])
                    m3.metric("Coordenadas", geo['lat_lon'])
                    try:
                        lat, lon = map(float, geo['lat_lon'].split(','))
                        st.map(pd.DataFrame({'lat': [lat], 'lon': [lon]}))
                    except:
                        st.warning("Falha ao renderizar mapa.")

                st.divider()

                st.subheader("🛡️ Reputação e Nível de Risco")
                if rep and "erro" not in rep:
                    r1, r2, r3 = st.columns(3)
                    score = rep['score_abuso']
                    r1.metric("Confiança de Abuso", f"{score}%", f"{rep['total_reportes']} reportes",
                              delta_color="normal" if score < 20 else "inverse")
                    r2.write(f"**Uso Detectado:** {rep['tipo_uso']}")
                    r3.write(f"**Domínio:** {rep.get('dominio', 'N/A')}")
                else:
                    st.info("ℹ️ Dados de reputação não disponíveis.")

                if ame:
                    st.write("---")
                    a1, a2, a3 = st.columns(3)
                    a1.warning(f"🎭 **VPN/Proxy:** {ame['e_proxy_vpn']}")
                    a2.info(f"☁️ **DataCenter:** {ame['e_data_center']}")
                    a3.success(f"📱 **Móvel:** {ame['e_movel']}")

                st.divider()

                st.subheader("🔍 Inteligência de Portas (Shodan)")
                if "erro" not in sho:
                    st.success(f"✅ Dados obtidos para: {target_externo}")
                    c1, c2 = st.columns(2)
                    with c1:
                        st.write("**🖥️ OS Detectado:**", sho['os'])
                        st.write("**🔌 Portas Abertas:**", sho['portas'] if sho['portas'] else "Nenhuma detectada")
                    with c2:
                        st.write("**📛 Hostnames:**", sho['hostnames'] if sho['hostnames'] else "Nenhum listado")
                    if sho['vulnerabilidades']:
                        st.warning("⚠️ **Vulnerabilidades Críticas (CVEs):**")
                        st.write(sho['vulnerabilidades'])
                else:
                    st.info(f"ℹ️ Shodan: {sho['erro']}")
        else:
            st.warning("Por favor, insira um IP ou Domínio válido.")

# --- MÓDULO: VEKTOR ---
elif modo == "💣 Vektor (Exploits & Arsenal)":
    st.header("💣 Vektor: Arsenal de Exploração")
    if st.session_state.dados_scan:
        if st.button("🔥 Gerar Plano de Ataque"):
            arsenal = st.session_state.vektor.buscar_exploits_locais(st.session_state.dados_scan)
            st.text_area("Lista de Exploração", arsenal, height=500)
    else:
        st.warning("⚠️ Faça um scan no Orion primeiro.")

# --- MÓDULO: AEGIS ---
elif modo == "🛡️ Aegis (Plano de Defesa)":
    st.header("🛡️ Aegis: Inteligência de Remediação")
    if st.session_state.dados_scan:
        if st.button("🛠️ Gerar Protocolo de Correção"):
            plano = st.session_state.aegis.gerar_guia_correcao(st.session_state.dados_scan)
            st.text_area("Guia de Defesa", plano, height=500)
            st.download_button("📥 Baixar TXT", plano, "remediacao.txt")
    else:
        st.warning("⚠️ Realize um scan no Orion primeiro.")

# --- MÓDULO: PHANTOM ---
elif modo == "👁 Phantom (Social)":
    st.header("👁 Engenharia Social")
    texto = st.text_area("Análise de Texto:")
    if st.button("🔍 Analisar"):
        st.text(st.session_state.phantom.analisar_social(texto))

# --- MÓDULO: INTELLIGENCE HUB ---
elif modo == "⚙️ Intelligence Hub":
    st.header("⚙️ Central de Inteligência")
    dados = st.session_state.sync.carregar_inteligencia_local()

    if "erro" in dados:
        st.error(dados["erro"])
    else:
        st.write(f"🕒 **Última Sincronização:** {dados.get('ultima_sincronizacao', 'N/A')}")
        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🔎 Scripts Nmap Ativos")
            scripts = dados.get("nmap_scripts", [])
            if scripts:
                for s in scripts:
                    st.code(s)
            else:
                st.info("Nenhum script carregado.")

            st.subheader("💣 Exploits Mapeados")
            exploits = dados.get("exploits", {})
            if exploits:
                for alvo, info in exploits.items():
                    st.write(f"**{alvo}** → `{info.get('script','?')}` via {info.get('tool','?')}")
            else:
                st.info("Nenhum exploit mapeado.")

        with col2:
            st.subheader("🛡️ Remediações Carregadas")
            remediacoes = dados.get("remediacoes", {})
            if remediacoes:
                for porta, passos in remediacoes.items():
                    st.write(f"**Porta/Serviço {porta}:**")
                    for p in passos:
                        st.write(f"  • {p}")
            else:
                st.info("Nenhuma remediação carregada.")