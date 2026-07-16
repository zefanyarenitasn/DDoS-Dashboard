import streamlit as st
import pandas as pd
import time
# (Pastikan load model ddos_model.pkl di sini)

# 1. Inisialisasi Memori Blacklist
if 'blacklist_ips' not in st.session_state:
    st.session_state.blacklist_ips = []

st.title("DDoS Monitoring Dashboard")
st.write("Live traffic intelligence & DDoS threat assessment")

# 2. BUAT WADAH KOSONG UNTUK METRIK LIVE
col1, col2, col3 = st.columns(3)
metric_total = col1.empty()
metric_normal = col2.empty()
metric_ddos = col3.empty()

# Tampilan awal Metrik (di-set 0 semua)
metric_total.metric("TOTAL REQUESTS", 0)
metric_normal.metric("NORMAL TRAFFIC", 0)
metric_ddos.metric("DDOS DETECTED", 0)

st.markdown("---")
st.subheader("🚫 Daftar Hitam IP (Blacklisted)")
tempat_tabel = st.empty()

# Render tabel jika sudah ada isinya
if len(st.session_state.blacklist_ips) > 0:
    df_awal = pd.DataFrame({
        "IP Penyerang (Diblock)": st.session_state.blacklist_ips,
        "Status": "DROP (iptables)"
    })
    tempat_tabel.dataframe(df_awal, use_container_width=True)
else:
    tempat_tabel.info("Belum ada IP yang diblokir. Jaringan aman.")

# 3. LOGIKA MONITORING BERSAMAAN
if st.button("Mulai Monitoring Trafik"):
    # Siapkan variabel penghitung live
    count_total = 0
    count_normal = 0
    count_ddos = 0
    
    # Ambil sampel dari dataset
    df = pd.read_parquet("Data/Syn-training.parquet")
    df_demo = df.sample(n=150, random_state=42) # Kita coba 150 request sesuai gambarmu
    
    st.write("---")
    status_box = st.empty()
    
    for index, row in df_demo.iterrows():
        # Tambah hitungan total request
        count_total += 1
        
        # Ambil IP (Ingat: sesuaikan 'Source IP' dengan nama kolom aslimu)
        ip_sumber = row.get('Source IP', f"192.168.1.{index % 255}") 
        
        # Ekstraksi fitur dan prediksi
        fitur = row.drop(['Label', 'Source IP'], errors='ignore')
        fitur_model = fitur[model.feature_names_in_].values.reshape(1, -1)
        prediksi = model.predict(fitur_model)[0]
        
        status_box.info(f"⏳ Menganalisis IP: {ip_sumber}...")
        
        # Cek hasil deteksi
        if prediksi == 1: 
            count_ddos += 1
            if ip_sumber not in st.session_state.blacklist_ips:
                st.session_state.blacklist_ips.append(ip_sumber) 
                
                # Update Tabel Live
                df_update = pd.DataFrame({
                    "IP Penyerang (Diblock)": st.session_state.blacklist_ips,
                    "Status": "DROP (iptables)"
                })
                tempat_tabel.dataframe(df_update, use_container_width=True)
        else:
            count_normal += 1

        # 4. UPDATE METRIK SECARA LIVE!
        metric_total.metric("TOTAL REQUESTS", count_total)
        metric_normal.metric("NORMAL TRAFFIC", count_normal)
        metric_ddos.metric("DDOS DETECTED", count_ddos)
        
        time.sleep(0.1) # Dipercepat sedikit biar nunggu 150 datanya gak kelamaan
        
    status_box.success("✅ Pemantauan selesai.")

if st.button("Bersihkan Blacklist"):
    st.session_state.blacklist_ips = []
    st.rerun()
