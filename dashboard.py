import streamlit as st
import pandas as pd

st.set_page_config(page_title="Network Monitor", layout="wide")

# Title
st.markdown("""
# 📡 Network Traffic Monitoring Dashboard
### Real-Time Network Analysis & Visualization
""")

# Sidebar
st.sidebar.title("📡 Network Monitor")
st.sidebar.write("Live Traffic Analysis")
st.sidebar.write("Status: 🟢 Running")

# Load data
try:
    df = pd.read_csv("traffic_log.csv", names=[
        "Time", "Source", "Destination", "Protocol",
        "Port", "Service", "Size", "PPS"
    ])
except:
    st.warning("No data yet. Run main.py first.")
    st.stop()

# Metrics
col1, col2 = st.columns(2)

with col1:
    st.metric("📦 Total Packets", len(df))

with col2:
    st.metric("⚡ Packets/sec", round(df["PPS"].iloc[-1], 2))

st.divider()

# Protocol Distribution
st.subheader("📊 Protocol Distribution")
protocol_counts = df["Protocol"].value_counts()
st.bar_chart(protocol_counts)

st.divider()

# Top IPs
st.subheader("👤 Top Active IPs")
top_ips = df["Source"].value_counts().head(5)
st.dataframe(top_ips)

st.divider()

# Service Distribution
st.subheader("🌐 Service Distribution")
service_counts = df["Service"].value_counts()
st.bar_chart(service_counts)

st.divider()

# Packet Size Trend
st.subheader("📈 Packet Size Trend")
st.line_chart(df["Size"])

st.divider()

# Packets per second
st.subheader("⚡ Packets Per Second")
st.line_chart(df["PPS"])