import streamlit as st
import re
import json
import requests
import datetime
from PIL import Image
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# ==========================================
# 核心設定與 UI 初始化
# ==========================================
# 💡 修復 1：加入 initial_sidebar_state="expanded" 強制預設展開側邊欄
st.set_page_config(
    page_title="釣魚信件緩衝分析器 V2", 
    layout="wide", 
    page_icon="🛡️",
    initial_sidebar_state="expanded" 
)

# 💡 修復 2：拿掉 header 隱藏設定，保留展開側邊欄的控制按鈕
hide_streamlit_style = "<style>#MainMenu {visibility: hidden;} footer {visibility: hidden;}</style>"
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

st.title("🛡️ 進階社交工程與釣魚訊息緩衝分析器")
st.markdown("結合 **Google Gemini 視覺分析** 與 **VirusTotal 情資**，支援動態時間校正與 SharePoint 真偽辨識！")

# ==========================================
# 側邊欄：API 金鑰設定
# ==========================================
with st.sidebar:
    st.header("⚙️ 系統與 API 設定")
    gemini_api_key = st.text_input("輸入 Google Gemini API Key", type="password")
    vt_api_key = st.text_input("輸入 VirusTotal API Key (選填)", type="password", help="提供以啟用外部網址掃描")
    st.markdown("---")
    st.markdown("💡 **V2.0 更新亮點**")
    st.markdown("- 🕒 **動態時間校正**：AI 具備真實世界時間感知。\n- ☁️ **SharePoint 雷達**：專抓偽造的微軟雲端分享與假登入畫面。")

# ==========================================
# 資料結構定義 (Pydantic Schema)
# ==========================================
class ThreatAnalysisResult(BaseModel):
    risk_score: int = Field(description="風險分數，範圍 0 到 100，越高代表越危險。")
    tactics_used: list[str] = Field(description="社交工程戰術列表，如 '時間壓力', '權威偽裝' 等。")
    logic_flaws: str = Field(description="用白話文點出這段訊息邏輯上不合理或可疑的地方。")
    sharepoint_status: str = Field(description="針對 SharePoint 或雲端硬碟的專屬分析結果。若無關則填寫未偵測。")
    extracted_urls: list[str] = Field(description="從文字或圖片中看到的網址(URL)列表。")
    recommended_action: str = Field(description="給予使用者的具體防範建議。")

# ==========================================
# 核心功能模組 (包含提示詞生成邏輯)
# ==========================================
def get_threat_analysis_prompt(text_content, has_image=False):
    """動態生成威脅分析的 Prompt，包含當前時間校正與 SharePoint 專屬指令"""
    today_date = datetime.date.today().strftime("%Y年%m月%d日")
    
    prompt_parts = [
        f"""你現在是一位資深的資安專家與數位鑑識分析師。
【重要時間基準】：今天的真實日期是 {today_date}。請務必以此時間點為絕對基準，判斷訊息中所提及的日期是否為過期、不合理，或是惡意偽造的未來日期。"""
    ]

    sharepoint_instructions = """
【專項任務：SharePoint 與雲端分享釣魚檢測】
若使用者提供的內容（無論是文字或截圖）與「文件分享、SharePoint、OneDrive、Google Drive」有關，請嚴格執行以下鑑識，並將結果詳細寫入 JSON 的 `sharepoint_status` 欄位：
1. 寄件人網域查核：若有寄件人資訊，其網域是否與宣稱的組織（如微軟）相符？
2. 網址列/連結特徵：檢查截圖中的網址列或文字中的連結，是否為真實官方網域（如 *.sharepoint.com），還是使用了相似字元的偽造網域（如 sharepoint-online-login.com、短網址等）？
3. 異常驗證要求：是否出現不合理的登入要求？（例如：只是要查看一份普通分享文件，卻要求輸入 Email 的密碼，這是典型的 AiTM 憑證竊取特徵）。
若無關雲端分享，請在該欄位填寫 '未偵測到相關雲端分享特徵'。"""
    
    prompt_parts.append(sharepoint_instructions)

    prompt_parts.append("""
請仔細分析使用者提供的內容，判斷這是否為社交工程攻擊或釣魚訊息。
請嚴格按照要求的 JSON 結構回傳分析結果，包含風險分數、使用的心理戰術、邏輯漏洞、以及具體的防範建議。如果從文字或圖片中看到任何網址(URL)，請務必將其列入 `extracted_urls` 陣列中。""")

    if text_content:
        prompt_parts.append(f"\n【使用者提供的文字內容】：\n{text_content}")
    if has_image:
        prompt_parts.append("\n【使用者同時上傳了截圖，請運用 OCR 與視覺能力進行綜合判斷】")

    return "\n".join(prompt_parts)

def extract_urls_from_text(text):
    if not text: return []
    return re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+').findall(text)

def check_virustotal(urls, vt_key):
    if not vt_key or not urls: return {}
    vt_results, headers = {}, {"x-apikey": vt_key}
    for url in urls:
        try:
            api_url = f"https://www.virustotal.com/api/v3/urls/{requests.utils.quote(url, safe='')}"
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                vt_results[url] = {"malicious": stats.get('malicious', 0), "status": "ok"}
            elif response.status_code == 404:
                vt_results[url] = {"status": "not_found", "message": "無紀錄"}
            else:
                vt_results[url] = {"status": "error", "message": f"API 錯誤代碼: {response.status_code}"}
        except Exception as e:
            vt_results[url] = {"status": "error", "message": str(e)}
    return vt_results

def analyze_threat(api_key, text_content=None, image_input=None):
    client = genai.Client(api_key=api_key)
    
    # 使用上方的函數動態生成 Prompt
    final_prompt = get_threat_analysis_prompt(text_content, image_input is not None)
    
    contents = [final_prompt]
    if image_input: contents.append(image_input)
        
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
            continue
    raise Exception("無法連線至 Gemini API，請檢查金鑰或網路。")

# ==========================================
# 網頁互動區塊
# ==========================================
tab1, tab2 = st.tabs(["📝 貼上純文字", "🖼️ 上傳可疑截圖 (支援 SharePoint 辨識)"])

with tab1: user_input_text = st.text_area("✍️ 貼上可疑訊息內容：", height=150)
with tab2:
    uploaded_file = st.file_uploader("📂 上傳截圖 (支援 PNG, JPG)", type=["png", "jpg", "jpeg"])
    if uploaded_file: st.image(Image.open(uploaded_file), width=300)

if st.button("🚀 開始深度分析", type="primary", use_container_width=True):
    if not gemini_api_key: st.error("⚠️ 請先於左側邊欄輸入 Google Gemini API Key。")
    elif not user_input_text.strip() and not uploaded_file: st.warning("⚠️ 請輸入文字或上傳圖片。")
    else:
        with st.spinner("系統深度分析中（包含 SharePoint 真偽驗證）..."):
            try:
                img_for_ai = Image.open(uploaded_file) if uploaded_file else None
                ai_result = analyze_threat(gemini_api_key, user_input_text.strip() if user_input_text else None, img_for_ai)
                
                urls_to_check = list(set(ai_result.get("extracted_urls", []) + extract_urls_from_text(user_input_text)))
                vt_result = check_virustotal(urls_to_check, vt_api_key)
                
                st.markdown("---")
                st.subheader("📊 綜合分析報告")
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    score = ai_result.get("risk_score", 0)
                    if score > 70: st.error(f"## 🚨 高度風險 ({score}/100)")
                    elif score > 30: st.warning(f"## ⚠️ 中度可疑 ({score}/100)")
                    else: st.success(f"## ✅ 風險較低 ({score}/100)")
                    st.markdown("**偵測到的心理戰術：**")
                    for tactic in ai_result.get("tactics_used", []): st.markdown(f"- 🚩 {tactic}")

                with col2:
                    st.markdown("#### ☁️ SharePoint / 雲端文件分析")
                    st.warning(ai_result.get("sharepoint_status", "未偵測到相關特徵。"))
                    
                    st.markdown("#### 🧠 AI 邏輯解析")
                    st.info(ai_result.get("logic_flaws", ""))
                    st.markdown("#### 🛡️ 具體防範建議")
                    st.success(ai_result.get("recommended_action", ""))

                if urls_to_check:
                    st.markdown("### 🔗 網址安全掃描")
                    if not vt_api_key: st.warning("未提供 VirusTotal 金鑰，略過外部掃描。")
                    else:
                        for u, r in vt_result.items():
                            if r.get("status") == "ok" and r.get("malicious", 0) > 0:
                                st.error(f"**{u}** ➔ 🚨 {r.get('malicious')} 個引擎標記惡意！")
                            elif r.get("status") == "ok": st.success(f"**{u}** ➔ ✅ 尚未標記")
                            elif r.get("status") == "not_found": st.warning(f"**{u}** ➔ ⚠️ VirusTotal 無紀錄")
                                
            except Exception as e: st.error(f"❌ 分析發生錯誤：{str(e)}")
