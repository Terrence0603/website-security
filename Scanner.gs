// ==========================================
// 📡 外部 API 串接與掃描邏輯
// ==========================================

// ----------------------------------------------------
// 🕵️‍♂️ HTTP HEAD 快速跳轉破解 (備用方案)
// ----------------------------------------------------
function expandUrlQuick(url) {
  var currentUrl = url;
  for (var i = 0; i < 3; i++) {
    try {
      var response = UrlFetchApp.fetch(currentUrl, { followRedirects: false, muteHttpExceptions: true, method: 'head' });
      var code = response.getResponseCode();
      if (code === 301 || code === 302 || code === 303 || code === 307 || code === 308) {
        var location = response.getHeaders()['Location'];
        if (location) {
          if (location.startsWith('/')) { 
            var domainMatch = currentUrl.match(/^(https?:\/\/[^\/]+)/);
            if (domainMatch) location = domainMatch[1] + location;
          }
          currentUrl = location;
        } else break;
      } else break; 
    } catch(e) { break; }
  }
  return currentUrl;
}

// ----------------------------------------------------
// 🖥️ URLScan 動態沙盒解析 (解法 A：破解 JS 跳轉)
// ----------------------------------------------------
function resolveUrlWithUrlScan(originalUrl) {
  if (!URLSCAN_API_KEY) return { finalUrl: expandUrlQuick(originalUrl), urlScanLink: null, status: "no_key" };
  
  try {
    var searchApi = "https://urlscan.io/api/v1/search/?q=page.url:\"" + encodeURIComponent(originalUrl) + "\"&size=1";
    var searchRes = UrlFetchApp.fetch(searchApi, {muteHttpExceptions: true});
    if (searchRes.getResponseCode() === 200) {
      var searchData = JSON.parse(searchRes.getContentText());
      if (searchData.results && searchData.results.length > 0) {
        var latest = searchData.results[0];
        return { finalUrl: latest.page.url, urlScanLink: latest.result, status: "cached" };
      }
    }

    var submitApi = "https://urlscan.io/api/v1/scan/";
    var options = {
      "method": "post",
      "headers": { "API-Key": URLSCAN_API_KEY, "Content-Type": "application/json" },
      "payload": JSON.stringify({"url": originalUrl, "visibility": "public"}),
      "muteHttpExceptions": true
    };
    var res = UrlFetchApp.fetch(submitApi, options);
    var json = JSON.parse(res.getContentText());

    if (json.uuid) {
      var reportUrl = "https://urlscan.io/result/" + json.uuid + "/";
      return { finalUrl: expandUrlQuick(originalUrl), urlScanLink: reportUrl, status: "pending" };
    }
  } catch(e) {}
  
  return { finalUrl: expandUrlQuick(originalUrl), urlScanLink: null, status: "error" };
}

// ----------------------------------------------------
// 📂 提取附件並計算 SHA-256
// ----------------------------------------------------
function checkAttachmentsHash(attachments) {
  if (!VIRUSTOTAL_API_KEY) return [];
  var results = [];
  var maxAttachments = Math.min(attachments.length, 2); 
  
  for (var i = 0; i < maxAttachments; i++) {
    var att = attachments[i];
    var bytes = att.getBytes();
    var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
    var hash = digest.map(function(byte) { return ('0' + (byte & 0xFF).toString(16)).slice(-2); }).join('');
    
    try {
      var apiUrl = "https://www.virustotal.com/api/v3/files/" + hash;
      var options = { "method": "get", "headers": { "x-apikey": VIRUSTOTAL_API_KEY }, "muteHttpExceptions": true };
      var response = UrlFetchApp.fetch(apiUrl, options);
      var code = response.getResponseCode();
      var vtGuiUrl = "https://www.virustotal.com/gui/file/" + hash;
      
      if (code === 200) {
        var stats = JSON.parse(response.getContentText()).data.attributes.last_analysis_stats;
        results.push({ name: att.getName(), hash: hash, malicious: stats.malicious, status: "ok", vtLink: vtGuiUrl });
      } else if (code === 404) {
        results.push({ name: att.getName(), hash: hash, status: "not_found", vtLink: "https://www.virustotal.com/gui/home/file" });
      } else {
        results.push({ name: att.getName(), hash: hash, status: "error" });
      }
    } catch (e) { results.push({ name: att.getName(), hash: hash, status: "error" }); }
  }
  return results;
}

// ----------------------------------------------------
// 🌐 掃描 VirusTotal 網址 (整合 URLScan 沙盒)
// ----------------------------------------------------
function checkVirusTotal(urlItems) {
  if (!VIRUSTOTAL_API_KEY || urlItems.length === 0) return [];
  var results = [];
  
  urlItems.forEach(function(item) {
    var scanData = resolveUrlWithUrlScan(item.originalUrl);
    var safeUrl = sanitizeUrl(scanData.finalUrl);
    var domain = extractDomain(safeUrl);
    var urlId = Utilities.base64EncodeWebSafe(safeUrl).replace(/=+$/, '');
    var vtGuiUrl = "https://www.virustotal.com/gui/url/" + urlId;

    try {
      var apiUrl = "https://www.virustotal.com/api/v3/urls/" + urlId;
      var options = { "method": "get", "headers": { "x-apikey": VIRUSTOTAL_API_KEY }, "muteHttpExceptions": true };
      var response = UrlFetchApp.fetch(apiUrl, options);
      var code = response.getResponseCode();
      
      var resultObj = { original: item.originalUrl, safeUrl: safeUrl, text: item.text, domain: domain, urlScanLink: scanData.urlScanLink, urlScanStatus: scanData.status, vtLink: vtGuiUrl };
      
      if (code === 200) {
        resultObj.status = "ok";
        resultObj.malicious = JSON.parse(response.getContentText()).data.attributes.last_analysis_stats.malicious;
      } else if (code === 404) { resultObj.status = "not_found"; }
      else if (code === 429) { resultObj.status = "rate_limit"; }
      else { resultObj.status = "error"; }
      results.push(resultObj);
    } catch (e) { results.push({ original: item.originalUrl, status: "error" }); }
  });
  return results;
}