import streamlit as st
import requests
import streamlit.components.v1 as components

# Page config
st.set_page_config(page_title="Holy Bible", layout="wide")

# Minimal global styling for the app shell (cards use their own CSS inside iframe)
st.markdown("""
    <style>
        header, footer {visibility: hidden;}
        .stApp {background-color: #0f1c2e;}
        h1, .stMarkdown h1, .block-container h1 {color: #FFFFFF !important;}
        .stTextInput > div > div {
            background-color: #182a43;
            color: #e0e6ed;
            border: 1px solid #263b59;
            border-radius: 8px;
        }
        .stTextInput > label {color: #e0e6ed;}
        .stTextInput input {color: #e0e6ed;}
    </style>
""", unsafe_allow_html=True)

st.title("📖 Holy Bible")

# Search bar
search = st.text_input("🔍 Search by UID or IP")

# Fetch clients from API
API_URL = "http://217.129.170.191:3000/holy-bible"
try:
    response = requests.get(API_URL)
    response.raise_for_status()
    data = response.json()
except Exception as e:
    st.error(f"Erro ao buscar dados: {e}")
    st.stop()

# Apply search filter
if search:
    data = [c for c in data if search.lower() in c['uid'].lower() or search in c['ip']]

# Display in 3 columns
cols = st.columns(3)
for i, cliente in enumerate(data):
    with cols[i % 3]:
        components.html(
            f"""
            <script>
                function copiar(id, btnId) {{
                    navigator.clipboard.writeText(document.getElementById(id).innerText);
                    let btn = document.getElementById(btnId);
                    let original = btn.innerHTML;
                    btn.innerHTML = '✔️';
                    btn.style.backgroundColor = '#37b24d';
                    setTimeout(() => {{
                        btn.innerHTML = original;
                        btn.style.backgroundColor = '';
                    }}, 3000);
                }}
            </script>
            <style>
                html, body {{
                    margin: 0; padding: 0;
                    background-color: #0f1c2e;
                    font-family: 'Arial', sans-serif;
                    color: #e0e6ed;
                }}
                .card {{
                    margin-top: 20px;
                    background-color: #182a43;
                    border-radius: 12px;
                    padding: 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    border: 1px solid #263b59;
                    transition: transform 0.15s ease;
                }}
                .card:hover {{
                    transform: translateY(-3px);
                    box-shadow: 0 6px 16px rgba(0,0,0,0.2);
                }}
                .uid {{
                    font-size: 1.4rem;
                    font-weight: bold;
                    margin-bottom: 5px;
                    color: #4dabf7;
                }}
                .ip {{
                    font-size: 0.9rem;
                    margin: 10px 0 15px;
                    color: #9ba5b5;
                }}
                .label-row {{
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 8px;
                }}
                .label-text {{
                    font-weight: 600;
                    color: #74c0fc;
                }}
                .key {{
                    font-family: monospace;
                    font-size: 0.8rem;
                    background-color: #121f33;
                    padding: 12px;
                    border-radius: 8px;
                    white-space: pre-wrap;
                    word-break: break-word;
                    border: 1px solid #263b59;
                    color: #d0d8e2;
                    margin-bottom: 15px;
                }}
                .copy-button {{
                    background-color: #4dabf7;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 6px 12px;
                    cursor: pointer;
                    font-size: 0.9rem;
                    transition: all 0.2s ease-in-out;
                    box-shadow: 0 2px 6px rgba(0,0,0,0.1);
                }}
                .copy-button:hover {{
                    background-color: #339af0;
                    transform: scale(1.03);
                    box-shadow: 0 4px 10px rgba(0,0,0,0.2);
                }}
                .copy-button:active {{
                    transform: scale(0.98);
                }}
            </style>
            <div class='card'>
                <div class='uid'>{cliente['uid']}</div>
                <div class='ip'>IP: {cliente['ip']}</div>

                <div class='label-row'>
                    <div class='label-text'>🔐 Chave RSA:</div>
                    <button id='btn_rsa_{i}' class='copy-button' onclick="copiar('rsa_{i}', 'btn_rsa_{i}')">📋</button>
                </div>
                <div class='key' id='rsa_{i}'>{cliente['pk_rsa']}</div>

                <div class='label-row'>
                    <div class='label-text'>🔐 Chave ECC:</div>
                    <button id='btn_ecc_{i}' class='copy-button' onclick="copiar('ecc_{i}', 'btn_ecc_{i}')">📋</button>
                </div>
                <div class='key' id='ecc_{i}'>{cliente['pk_ecc']}</div>
            </div>
            """,
            height=620
        )
