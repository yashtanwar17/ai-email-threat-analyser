chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_eml") {
    try {
      const subject = document.querySelector('h2.hP')?.innerText 
                   || document.title.replace('- Gmail', '').trim() 
                   || 'No Subject';

      const senderEl = document.querySelector('.gD') || document.querySelector('[email]');
      const senderName = senderEl?.getAttribute('name') || senderEl?.innerText || 'Unknown';
      const senderEmail = senderEl?.getAttribute('email') || 'unknown@domain.com';

      // Capture message body containers
      let bodyText = "";
      const bodyContainers = document.querySelectorAll('.a3s.aiL, .a3s');
      bodyContainers.forEach(container => {
        if (container.innerText) bodyText += container.innerText + "\n";
      });

      if (!bodyText.trim()) {
        const main = document.querySelector('div[role="main"]');
        if (main) bodyText = main.innerText;
      }

      if (!bodyText.trim()) {
        sendResponse({ success: false, error: "Open an expanded email message inside Gmail first." });
        return true;
      }

      const emlContent = 
`From: "${senderName}" <${senderEmail}>
Subject: ${subject}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

${bodyText}`;

      sendResponse({
        success: true,
        emlContent: emlContent,
        filename: 'gmail_extracted.eml'
      });
    } catch (e) {
      sendResponse({ success: false, error: e.message });
    }
  }
  return true;
});
