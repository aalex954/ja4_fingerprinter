import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import sniff, TLSClientHello, TLSServerHello
from collections import defaultdict
import hashlib
import threading

# Global data storage for real-time and historical analysis
live_data = defaultdict(list)
historical_data = []

# Streamlit page configuration
st.set_page_config(page_title="JA4 Fingerprint Analyzer", layout="wide")

# Sidebar for navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Live Traffic", "Education", "Analytics"])

# Mutex for thread-safe access to data
data_lock = threading.Lock()

# Packet parsing function
def parse_ja4(packet):
    """
    Parses JA4 fingerprints from captured packets.
    """
    try:
        if packet.haslayer(TLSClientHello):
            ja4 = extract_ja4(packet[TLSClientHello])
            if ja4:
                with data_lock:
                    live_data["Timestamp"].append(packet.time)
                    live_data["Type"].append("JA4")
                    live_data["Fingerprint"].append(ja4)
                    historical_data.append((packet.time, "JA4", ja4))
        elif packet.haslayer(TLSServerHello):
            ja4l = extract_ja4l(packet[TLSServerHello])
            if ja4l:
                with data_lock:
                    live_data["Timestamp"].append(packet.time)
                    live_data["Type"].append("JA4L")
                    live_data["Fingerprint"].append(ja4l)
                    historical_data.append((packet.time, "JA4L", ja4l))
    except Exception as e:
        st.error(f"Error parsing packet: {e}")

def extract_ja4(tls_hello):
    """
    Extracts JA4 fingerprint from a TLS Client Hello packet.
    JA4 fingerprint comprises:
    - TLS version
    - Cipher suites
    - Extensions (IDs only)
    - Elliptic curves
    - Elliptic curve point formats
    """
    try:
        version = tls_hello.version
        cipher_suites = ",".join(map(str, tls_hello.ciphers))
        extensions = ",".join(str(ext.type) for ext in tls_hello.extensions)
        elliptic_curves = ",".join(
            str(curve.named_curve) for curve in tls_hello.extensions if hasattr(curve, "named_curve")
        )
        ec_point_formats = ",".join(
            str(fmt.ec_point_format) for fmt in tls_hello.extensions if hasattr(fmt, "ec_point_format")
        )

        ja4_string = f"{version},{cipher_suites},{extensions},{elliptic_curves},{ec_point_formats}"
        ja4_fingerprint = hashlib.md5(ja4_string.encode()).hexdigest()
        return ja4_fingerprint
    except Exception as e:
        print(f"Error extracting JA4: {e}")
        return None

def extract_ja4l(tls_hello):
    """
    Extracts JA4L fingerprint from a TLS Server Hello packet.
    JA4L fingerprint comprises:
    - TLS version
    - Cipher suite
    - Extensions (IDs only)
    """
    try:
        version = tls_hello.version
        cipher_suite = str(tls_hello.cipher_suite)
        extensions = ",".join(str(ext.type) for ext in tls_hello.extensions)

        ja4l_string = f"{version},{cipher_suite},{extensions}"
        ja4l_fingerprint = hashlib.md5(ja4l_string.encode()).hexdigest()
        return ja4l_fingerprint
    except Exception as e:
        print(f"Error extracting JA4L: {e}")
        return None

# Function to start sniffing traffic
def capture_traffic():
    sniff(prn=parse_ja4, filter="tcp port 443", store=0)

# Start packet capture in a separate thread
thread = threading.Thread(target=capture_traffic, daemon=True)
thread.start()

# Streamlit page rendering based on user selection
if page == "Live Traffic":
    st.title("Live Traffic")
    st.write("Displaying live JA4, JA4L, and JA4T fingerprints...")

    # Display live data
    with data_lock:
        live_df = pd.DataFrame(live_data)
        st.table(live_df)

elif page == "Education":
    st.title("Educational Content")
    st.write("""
        ### Understanding JA4, JA4L, and JA4T Fingerprints
        - **JA4**: Represents a fingerprint for TLS Client Hello messages, capturing specific TLS features.
        - **JA4L**: Represents the Server Hello fingerprint, similar to JA3S.
        - **JA4T**: A combination of client and server fingerprints that helps identify the nature of the connection.
        
        **Why these are important?**
        These fingerprints help in identifying client-server applications and potential security risks.
    """)

elif page == "Analytics":
    st.title("Analytics")
    st.write("Historical analytics of JA4, JA4L, and JA4T fingerprints...")

    # Display historical data
    with data_lock:
        hist_df = pd.DataFrame(historical_data, columns=["Timestamp", "Type", "Fingerprint"])
        st.table(hist_df)

    # Plot metrics
    fig, ax = plt.subplots()
    hist_df['Type'].value_counts().plot(kind='bar', ax=ax)
    ax.set_title("Distribution of Fingerprints")
    ax.set_xlabel("Fingerprint Type")
    ax.set_ylabel("Count")
    st.pyplot(fig)
