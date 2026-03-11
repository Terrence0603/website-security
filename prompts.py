import datetime

def get_threat_analysis_prompt(text_content, has_image=False):
    """
    動態生成威脅分析的 Prompt，包含當前時間校正與 SharePoint 專屬指令
    """
    # 取得當下真實時間，解決 AI 時間盲區問題
    today_date = datetime.date.today().strftime("%Y年%m月%d日")
    
    # 基礎 Prompt，注入當前時間
    prompt_parts = [
        f"""你現在是一位資深的資安專家與數位鑑識分析師。
【重要時間基準】：今天的真實日期是 {today_date}。請務必以此時間點為絕對基準，判斷訊息中所提及的日期是否為過期、不合理，或是惡意偽造的未來日期。"""
    ]

    # SharePoint / 雲端硬碟專屬鑑識指令
    sharepoint_instructions = """
【專項任務：SharePoint 與雲端分享釣魚檢測】
若使用者提供的內容（無論是文字或截圖）與「文件分享、SharePoint、OneDrive、Google Drive」有關，請嚴格執行以下鑑識，並將結果詳細寫入 JSON 的 `sharepoint_status` 欄位：
1. 寄件人網域查核：若有寄件人資訊，其網域是否與宣稱的組織（如微軟）相符？（例如：寄件人是 Gmail 或奇怪網域，卻自稱微軟系統，極度可疑）。
2. 網址列/連結特徵：檢查截圖中的網址列或文字中的連結，是否為真實官方網域（如 *.sharepoint.com），還是使用了相似字元的偽造網域（如 sharepoint-online-login.com、短網址等）？
3. 異常驗證要求：是否出現不合理的登入要求？（例如：只是要查看一份普通分享文件，卻要求輸入 Email 的密碼，這是典型的 AiTM 憑證竊取特徵）。
若無關雲端分享，請在該欄位填寫 '未偵測到相關雲端分享特徵'。"""
    
    prompt_parts.append(sharepoint_instructions)

    # 綜合分析指令
    prompt_parts.append("""
請仔細分析使用者提供的內容，判斷這是否為社交工程攻擊或釣魚訊息。
請嚴格按照要求的 JSON 結構回傳分析結果，包含風險分數、使用的心理戰術、邏輯漏洞、以及具體的防範建議。如果從文字或圖片中看到任何網址(URL)，請務必將其列入 `extracted_urls` 陣列中。""")

    # 附加使用者輸入的文字內容
    if text_content:
        prompt_parts.append(f"\n【使用者提供的文字內容】：\n{text_content}")
        
    if has_image:
        prompt_parts.append("\n【使用者同時上傳了截圖，請運用 OCR 與視覺能力進行綜合判斷】")

    return "\n".join(prompt_parts)
