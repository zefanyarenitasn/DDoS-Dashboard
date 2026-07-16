import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import time
import random
import joblib
from datetime import datetime
import streamlit as st
import pandas as pd
import time
# (import lainnya seperti joblib, sklearn dll)

# Membuat memori penyimpanan Blacklist IP jika belum ada
if 'blacklist_ips' not in st.session_state:
    st.session_state.blacklist_ips = []

# 1. PAGE CONFIGURATION
st.set_page_config(
    page_title="DDoS Monitoring Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 2. CSS — layout supaya dashboard muat dalam 1 layar
st.markdown(
    """
    <style>
        .block-container {
            padding-top: 0.8rem;
            padding-bottom: 0.3rem;
            max-height: 100vh;
        }
        [data-testid="stMetricValue"] {
            font-size: 1.4rem;
        }
        [data-testid="stMetricLabel"] {
            font-size: 0.8rem;
        }
        h1 {
            font-size: 1.4rem;
            margin-bottom: 0rem;
        }
        h3 {
            font-size: 0.95rem;
            margin-top: 0.1rem;
            margin-bottom: 0.3rem;
        }
        p, .stCaption {
            font-size: 0.85rem;
        }
        hr {
            margin: 0.4rem 0;
        }
        [data-testid="stSidebar"] h3 {
            font-size: 0.95rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# 3. DATA & MODEL LOADING (cached)
DATA_ROWS = 150          # jumlah baris data simulasi (urut, bukan diacak)
SIM_STEP_DELAY = 0.05    # kecepatan render per baris

COUNTRY_SEED = {
    "US": "United States",
    "CN": "China",
    "RU": "Russia",
    "DE": "Germany",
    "BR": "Brazil",
    "IN": "India",
    "GB": "United Kingdom",
}

# Level ancaman berdasarkan persentase (DDoS / Total Request)
THREAT_LEVELS = [
    {"name": "NORMAL", "min": 0, "max": 5, "color": "#10b981", "icon": "🟢"},
    {"name": "DEGRADED", "min": 6, "max": 25, "color": "#3b82f6", "icon": "🔵"},
    {"name": "DISRUPTED", "min": 26, "max": 50, "color": "#f59e0b", "icon": "🟡"},
    {"name": "SERVICE DOWN", "min": 51, "max": 80, "color": "#f97316", "icon": "🟠"},
    {"name": "BLACKHOLED", "min": 81, "max": 100, "color": "#ef4444", "icon": "🔴"},
]


def get_threat_level(score: float) -> dict:
    """Kembalikan info level ancaman (nama, warna, icon) sesuai persentase score."""
    for level in THREAT_LEVELS:
        if level["min"] <= score <= level["max"]:
            return level
    return THREAT_LEVELS[-1]


def hex_to_rgba(hex_color: str, alpha: float = 0.2) -> str:
    """Konversi '#rrggbb' -> 'rgba(r,g,b,a)' (Plotly tidak menerima hex 8-digit)."""
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


@st.cache_resource
def load_ml_engine():
    """Load model dan siapkan 150 baris data uji secara urut (bukan acak)."""
    model = joblib.load("Models/ddos_model.pkl")
    df_full = pd.read_parquet("Data/Syn-training.parquet")
    df_sample = df_full.sample(n=DATA_ROWS, random_state=42)
    df_features = df_sample.drop(columns=["Label"], errors="ignore")[model.feature_names_in_]
    return model, df_features


# 4. SESSION STATE
def init_session_state():
    defaults = {
        "current_index": 0,
        "simulasi_aktif": False,
        "tot_req": 0,
        "tot_norm": 0,
        "tot_ddos": 0,
        "logs": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

    if "country_stats" not in st.session_state:
        st.session_state.country_stats = {
            code: {"name": name, "req": 0} for code, name in COUNTRY_SEED.items()
        }


init_session_state()


def toggle_sim():
    st.session_state.simulasi_aktif = not st.session_state.simulasi_aktif


def reset_sim():
    st.session_state.simulasi_aktif = False
    st.session_state.current_index = 0
    st.session_state.tot_req = 0
    st.session_state.tot_norm = 0
    st.session_state.tot_ddos = 0
    st.session_state.logs = []
    for stats in st.session_state.country_stats.values():
        stats["req"] = 0


# 5. SIDEBAR
def render_sidebar():
    with st.sidebar:
        st.markdown("### CONTROL PANEL")
        sensitivity = st.slider("Sensitivity", 0.50, 1.00, 0.70)

        st.markdown("### 📊 MONITORING")
        if st.session_state.simulasi_aktif:
            st.button("⏹ STOP", on_click=toggle_sim, use_container_width=True)
        else:
            st.button("▶ START", on_click=toggle_sim, type="primary", use_container_width=True)
        st.button("Reset", on_click=reset_sim, use_container_width=True)

        status_icon = "🟢" if st.session_state.simulasi_aktif else "🔴"
        status_text = "ACTIVE" if st.session_state.simulasi_aktif else "IDLE"
        st.markdown(f"**{status_icon} Status: {status_text}**")

        st.markdown("### LEVEL GUIDE")
        st.markdown(
            "🟢 L1: NORMAL\n\n"
            "🔵 L2: DEGRADED\n\n"
            "🟡 L3: DISRUPTED\n\n"
            "🟠 L4: DOWN\n\n"
            "🔴 L5: BLACKHOLED"
        )

    return sensitivity


# 6. MAIN DASHBOARD SECTIONS
def render_header():
    st.title("DDoS Monitoring Dashboard")
    st.caption("Live traffic intelligence & DDoS threat assessment")


def render_metrics():
    c1, c2, c3 = st.columns(3)
    c1.metric("TOTAL REQUESTS", f"{st.session_state.tot_req:,}")
    c2.metric("NORMAL TRAFFIC", f"{st.session_state.tot_norm:,}")
    c3.metric("DDOS DETECTED", f"{st.session_state.tot_ddos:,}")
    st.markdown("<hr>", unsafe_allow_html=True)


def render_threat_meter():
    st.markdown("### 📈 THREAT METER")

    threat_score = 0
    if st.session_state.tot_req > 0:
        threat_score = (st.session_state.tot_ddos / st.session_state.tot_req) * 100

    level = get_threat_level(threat_score)

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=threat_score,
            number={"suffix": "%", "font": {"color": "white"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "white"},
                "bar": {"color": level["color"]},
                "bgcolor": "#262730",
                "borderwidth": 0,
                "steps": [
                    {"range": [lv["min"], lv["max"]], "color": hex_to_rgba(lv["color"], 0.2)}
                    for lv in THREAT_LEVELS
                ],
            },
        )
    )
    fig.update_layout(
        height=190,
        margin=dict(l=20, r=20, t=20, b=5),
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color": "white"},
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown(
        f"<div style='text-align:center; font-size:0.95rem; font-weight:600; "
        f"color:{level['color']}; margin-top:-0.6rem;'>"
        f"{level['icon']} LEVEL: {level['name']}</div>",
        unsafe_allow_html=True,
    )


def render_country_table():
    st.markdown("### 🌐 WEB TRAFFIC BY COUNTRY")

    rows = []
    for code, data in st.session_state.country_stats.items():
        pct = 0.0
        if st.session_state.tot_req > 0:
            pct = (data["req"] / st.session_state.tot_req) * 100
        rows.append(
            {
                "Country Code": code,
                "Country": data["name"],
                "Requests": data["req"],
                "Percentage": f"{pct:.1f}%",
            }
        )

    # height tetap -> tabel jadi scrollable di dalam kotaknya sendiri
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=200)


def render_event_log():
    st.markdown("### 📝 EVENT LOG")

    columns = ["Time", "IP Address", "Country", "Requests", "Status", "Message"]
    df_logs = pd.DataFrame(st.session_state.logs, columns=columns) if st.session_state.logs else pd.DataFrame(columns=columns)

    # height tetap -> event log jadi scrollable di dalam kotaknya sendiri
    st.dataframe(df_logs, use_container_width=True, hide_index=True, height=200)


# 7. SIMULATION ENGINE (real-time, 150 baris data urut)
def run_simulation_step(sensitivity: float):
    model_rf, data_bersih = load_ml_engine()

    if st.session_state.current_index >= len(data_bersih):
        st.session_state.simulasi_aktif = False
        st.rerun()
        return

    time.sleep(SIM_STEP_DELAY)

    i = st.session_state.current_index
    baris_tes = data_bersih.iloc[[i]]
    prob_ddos = model_rf.predict_proba(baris_tes)[0][1]
    is_ddos = prob_ddos >= sensitivity

    st.session_state.tot_req += 1

    if is_ddos:
        st.session_state.tot_ddos += 1
        status, msg = "DDoS", f"SYN Flood ({prob_ddos * 100:.1f}%)"
        ip_addr = f"{random.choice([185, 220, 103, 45])}.{i % 250}.{random.randint(10, 99)}.1"
    else:
        st.session_state.tot_norm += 1
        status, msg = "Normal", f"Normal Traffic ({prob_ddos * 100:.1f}%)"
        ip_addr = f"192.168.1.{i % 50 + 1}"

    country_code = random.choice(list(st.session_state.country_stats.keys()))
    st.session_state.country_stats[country_code]["req"] += 1

    new_log = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "IP Address": ip_addr,
        "Country": st.session_state.country_stats[country_code]["name"],
        "Requests": 1,
        "Status": status,
        "Message": msg,
    }
    st.session_state.logs.insert(0, new_log)

    st.session_state.current_index += 1
    st.rerun()


# 8. MAIN
def main():
    sensitivity = render_sidebar()

    render_header()
    render_metrics()

    col_left, col_right = st.columns([1, 1.2], gap="large")
    with col_left:
        render_threat_meter()
    with col_right:
        render_country_table()

    render_event_log()

    if st.session_state.simulasi_aktif:
        run_simulation_step(sensitivity)


if __name__ == "__main__":
    main()

st.subheader("🛡️ Simulasi Auto-Blocking (Dataset)")
st.write("Sistem membaca aliran data dari dataset dan melakukan eksekusi pemblokiran secara real-time.")

if st.button("Mulai Monitoring Trafik"):
    # 1. Baca dataset
    df = pd.read_parquet("Data/Syn-training.parquet")
    
    # 2. Ambil sampel acak (misal 30 paket) untuk demo
    df_demo = df.sample(n=30, random_state=42)
    
    # Tempat penampung UI agar teksnya bisa update otomatis (tidak berjejer ke bawah)
    status_box = st.empty()
    alert_box = st.empty()
    
    st.write("---")
    st.markdown("**Status Eksekusi:**")
    
    # 3. Looping membaca paket satu per satu
    for index, row in df_demo.iterrows():
        # WARNING: Sesuaikan 'Source IP' dengan nama kolom IP di datasetmu!
        # Jika di dataset tidak ada kolom IP, kita buat IP dummy untuk keperluan demo simulasi
        ip_sumber = row.get('Source IP', f"192.168.1.{index % 255}") 
        
        # 4. Siapkan fitur untuk ditebak model (Buang kolom Label dan kolom non-numerik)
        fitur = row.drop(['Label', 'Source IP'], errors='ignore')
        
        # Pastikan kolom sesuai dengan model saat training
        fitur_model = fitur[model.feature_names_in_].values.reshape(1, -1)
        
        # 5. Model melakukan tebakan
        prediksi = model.predict(fitur_model)[0]
        
        status_box.info(f"⏳ Memeriksa paket masuk dari IP: {ip_sumber}...")
        time.sleep(0.3) # Memberikan jeda 0.3 detik agar terlihat seperti real-time
        
        # 6. Logika Mitigasi (Auto-Blocking)
        if prediksi == 1: # Jika terdeteksi sebagai SYN Flood
            if ip_sumber not in st.session_state.blacklist_ips:
                st.session_state.blacklist_ips.append(ip_sumber) # Masukkan ke memori Blacklist
                
                # Simulasi notifikasi peringatan
                alert_box.error(f"🚨 ANOMALI TERDETEKSI! Memblokir IP {ip_sumber} (iptables DROP)")
                time.sleep(0.5) # Tahan peringatan sebentar agar terbaca
        else:
            alert_box.success(f"✅ Aman. Trafik normal dari IP {ip_sumber} dilewatkan.")
