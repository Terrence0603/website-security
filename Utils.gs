// ==========================================
// 🛠️ 工具箱：字串與網址處理
// ==========================================

function sanitizeUrl(url) {
  return url.split('?')[0].split('#')[0];
}

function extractDomain(url) {
  var match = url.match(/^https?:\/\/([^/?#]+)(?:[/?#]|$)/i);
  return match ? match[1] : url;
}

function extractUrlsWithContext(plainBody, htmlBody) {
  var extractedItems = [];
  var seenUrls = new Set();
  var aTagRegex = /<a\s+([^>]*href=["'](https?:\/\/[^"']+)["'][^>]*)>([\s\S]*?)<\/a>/gi;
  var match;
  
  while ((match = aTagRegex.exec(htmlBody)) !== null) {
    var url = match[2];
    var innerHtml = match[3];
    var contextText = innerHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || "[圖片/隱藏按鈕]";
    
    if (!seenUrls.has(url)) {
      seenUrls.add(url);
      extractedItems.push({ originalUrl: url, text: contextText });
    }
  }
  return extractedItems.filter(function(item) {
    var lowerU = item.originalUrl.toLowerCase();
    return !lowerU.includes('w3.org') && !lowerU.includes('schemas.microsoft.com') && !lowerU.includes('gstatic.com');
  }).slice(0, 2); 
}