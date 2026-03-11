import streamlit as st
import re
import json
import requests
from PIL import Image
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# ==========================================
# 核心設定與 UI 初始化
# ==========================================
st.set_page_config(page_title="進階釣魚信件緩衝分析器 (支援截圖)", layout="wide", page_icon="🛡️")

hide_streamlit_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}
</style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.title("🛡️ 進階社交工程與釣魚訊息緩衝分析器")
st.markdown("結合 **Google Gemini 視覺與結構化分析** 及 **VirusTotal 威脅情資**，支援直接上傳可疑對話截圖！")

# ==========================================
# 側邊欄：API 金鑰設定
# ==========================================
with st.sidebar:
    st.header("⚙️ 系統與 API 設定")
    gemini_api_key = st.text_input("輸入 Google Gemini API Key", type="password")
    vt_api_key = st.text_input("輸入 VirusTotal API Key (選填)", type="password", help="若提供此金鑰，系統將自動比對全球威脅資料庫。")
    st.markdown("---")
    st.markdown("💡 **使用提示**")
    st.markdown("您可以直接貼上文字，或上傳 LINE、Email 的截圖進行分析。AI 會自動讀取圖片中的文字與隱含風險。")

# ==========================================
# 資料結構定義 (Pydantic Schema for Gemini)
# ==========================================
class ThreatAnalysisResult(BaseModel):
    risk_score: int = Field(description="風險分數，範圍 0 到 100，越高代表越危險。")
    tactics_used: list[str] = Field(description="訊息中使用的社交工程戰術列表，例如 '時間壓力', '權威偽裝', '利益誘惑' 等。")
    logic_flaws: str = Field(description="用白話文點出這段訊息邏輯上不合理或可疑的地方，約 2 到 3 句話。")
    extracted_urls: list[str] = Field(description="如果從文字或圖片中看到任何網址(URL)，請列出。若無則為空列表。")
    recommended_action: str = Field(description="給予使用者的具體防範建議。")

# ==========================================
# 核心功能模組
# ==========================================

def extract_urls_from_text(text):
    """(備用)從純文字中提取 URL"""
    if not text: return []
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    return url_pattern.findall(text)

def check_virustotal(urls, vt_key):
    """呼叫 VirusTotal API 檢查網址"""
    if not vt_key or not urls:
        return {}
    
    vt_results = {}
    headers = {"x-apikey": vt_key}
    
    for url in urls:
        try:
            api_url = f"https://www.virustotal.com/api/v3/urls/{requests.utils.quote(url, safe='')}"
            response = requests.get(api_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious_count = stats.get('malicious', 0)
                vt_results[url] = {"malicious": malicious_count, "status": "ok"}
            elif response.status_code == 404:
                vt_results[url] = {"status": "not_found", "message": "無紀錄"}
            else:
                vt_results[url] = {"status": "error", "message": f"API 錯誤代碼: {response.status_code}"}
        except Exception as e:
            vt_results[url] = {"status": "error", "message": str(e)}
            
    return vt_results

def analyze_threat(api_key, text_content=None, image_input=None):
    """使用 Gemini 分析純文字或圖片，並強制回傳結構化 JSON"""
    client = genai.Client(api_key=api_key)
    
    # 建立多模態的 Content 清單
    contents = []
    
    base_prompt = """
    你現在是一位資深的資安專家。請仔細分析使用者提供的內容（可能是純文字或圖片截圖），判斷這是否為社交工程攻擊或釣魚訊息。
    如果是圖片，請運用你的視覺能力（OCR）讀取圖片中的文字與介面元素進行判斷。
    請嚴格按照要求的 JSON 結構回傳分析結果。
    """
    contents.append(base_prompt)
    
    if text_content:
        contents.append(f"【使用者輸入的文字內容】：\n{text_content}")
    
    if image_input:
        contents.append("【使用者上傳的截圖】：")
        contents.append(image_input)
        
    # 優先使用具備強大多模態能力的 Pro 模型
    models_to_try = ['gemini-2.5-pro', 'gemini-2.5-flash']
    
    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=contents,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ThreatAnalysisResult,
                    temperature=0.1
                ),
            )
            return json.loads(response.text)
        except Exception as e:
            st.toast(f"模型 {model_name} 分析失敗，嘗試降級...")
            continue
            
    raise Exception("無法連線至 Gemini API 進行分析，請檢查金鑰或嘗試上傳較小的圖片。")

# ==========================================
# 網頁互動區塊
# ==========================================

# 提供兩種輸入方式的頁籤
tab1, tab2 = st.tabs(["📝 貼上純文字", "🖼️ 上傳可疑截圖"])

with tab1:
    user_input_text = st.text_area("✍️ 貼上可疑訊息內容：", height=150, key="text_input")

with tab2:
    uploaded_file = st.file_uploader("📂 上傳 LINE 或 Email 截圖 (支援 PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file is not None:
        # 顯示使用者上傳的圖片預覽
        image_preview = Image.open(uploaded_file)
        st.image(image_preview, caption="上傳的截圖預覽", width=300)

if st.button("🚀 開始深度分析", type="primary", use_container_width=True):
    # 防呆檢查
    if not gemini_api_key:
        st.error("⚠️ 請先於左側邊欄輸入您的 Google Gemini API Key。")
    elif not user_input_text.strip() and uploaded_file is None:
        st.warning("⚠️ 請輸入文字或上傳一張圖片來進行分析。")
    else:
        with st.spinner("系統深度分析中（包含圖片解析），這可能需要幾秒鐘..."):
            try:
                # 準備要送給 AI 的圖片物件 (如果有上傳的話)
                img_for_ai = Image.open(uploaded_file) if uploaded_file else None
                
                # 1. 呼叫 Gemini AI 進行多模態分析
                ai_result = analyze_threat(
                    api_key=gemini_api_key, 
                    text_content=user_input_text.strip() if user_input_text else None,
                    image_input=img_for_ai
                )
                
                # 2. 整合網址：從 AI 結構化輸出中拿網址，或從純文字中用正則表達式拿
                urls_to_check = ai_result.get("extracted_urls", [])
                if user_input_text:
                    urls_to_check.extend(extract_urls_from_text(user_input_text))
                urls_to_check = list(set(urls_to_check)) # 移除重複的網址
                
                # 3. 呼叫 VirusTotal 檢查網址
                vt_result = check_virustotal(urls_to_check, vt_api_key)
                
                # --- 渲染結果畫面 ---
                st.markdown("---")
                st.subheader("📊 綜合分析報告")
                
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    score = ai_result.get("risk_score", 0)
                    if score > 70:
                        st.error(f"## 🚨 高度風險 ({score}/100)")
                    elif score > 30:
                        st.warning(f"## ⚠️ 中度可疑 ({score}/100)")
                    else:
                        st.success(f"## ✅ 風險較低 ({score}/100)")
                        
                    st.markdown("**偵測到的心理戰術：**")
                    for tactic in ai_result.get("tactics_used", []):
                        st.markdown(f"- 🚩 {tactic}")

                with col2:
                    st.markdown("#### 🧠 AI 邏輯解析")
                    st.info(ai_result.get("logic_flaws", "無明顯邏輯漏洞。"))
                    
                    st.markdown("#### 🛡️ 具體防範建議")
                    st.success(ai_result.get("recommended_action", "保持警覺。"))

                if urls_to_check:
                    st.markdown("### 🔗 網址安全掃描")
                    if not vt_api_key:
                        st.warning("已偵測到網址，但未提供 VirusTotal 金鑰，因此略過外部情資掃描。")
                        for u in urls_to_check: st.code(u)
                    else:
                        for u, r in vt_result.items():
                            if r.get("status") == "ok":
                                if r.get("malicious", 0) > 0:
                                    st.error(f"**{u}** ➔ 🚨 {r.get('malicious')} 個引擎標記惡意！")
                                else:
                                    st.success(f"**{u}** ➔ ✅ 尚未標記")
                            elif r.get("status") == "not_found":
                                st.warning(f"**{u}** ➔ ⚠️ VirusTotal 無紀錄，請小心。")
                            else:
                                st.info(f"**{u}** ➔ 掃描失敗。")
                                
            except Exception as e:
                st.error(f"❌ 分析發生錯誤：{str(e)}")