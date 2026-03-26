// ==========================================
// ⚙️ 系統設定：安全讀取隱藏的 API 金鑰
// ==========================================
var scriptProperties = PropertiesService.getScriptProperties();
var GEMINI_API_KEY = scriptProperties.getProperty('GEMINI_API_KEY');
var VIRUSTOTAL_API_KEY = scriptProperties.getProperty('VIRUSTOTAL_API_KEY');
var URLSCAN_API_KEY = scriptProperties.getProperty('URLSCAN_API_KEY');