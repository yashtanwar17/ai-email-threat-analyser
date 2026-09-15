document.getElementById('scanBtn').addEventListener('click', async () => {
  const verdictDiv = document.getElementById('verdict');
  const resultCard = document.getElementById('resultCard');
  const scoreBadge = document.getElementById('scoreBadge');
  const indicatorsList = document.getElementById('indicators');

  resultCard.style.display = 'block';
  verdictDiv.innerText = 'Extracting .eml file from Gmail...';
  verdictDiv.style.color = '#0f172a';
  scoreBadge.className = 'score-value';
  scoreBadge.innerText = '-/10';
  indicatorsList.innerHTML = '';

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab || !tab.url || !tab.url.includes("mail.google.com")) {
    verdictDiv.innerText = 'Please switch to an active Gmail tab first.';
    return;
  }

  const sendToWebPipeline = async (response) => {
    if (!response || !response.success) {
      verdictDiv.innerText = response?.error || 'Could not capture email from DOM.';
      return;
    }

    verdictDiv.innerText = 'Uploading .eml to forensic backend...';

    // 1. Package .eml file in memory
    const emlBlob = new Blob([response.emlContent], { type: 'message/rfc822' });
    const emlFile = new File([emlBlob], response.filename, { type: 'message/rfc822' });

    const formData = new FormData();
    formData.append('file', emlFile);

    try {
      // 2. Post file directly to existing /analyze route
      const uploadRes = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        body: formData
      });

      if (!uploadRes.ok) {
        const errorText = await uploadRes.text();
        verdictDiv.innerText = `Analysis failed (HTTP ${uploadRes.status}). Check terminal.`;
        console.error("Server Error:", errorText);
        return;
      }

      const { report_id } = await uploadRes.json();
      if (!report_id) {
        verdictDiv.innerText = 'Failed: Backend did not issue a report ID.';
        return;
      }

      verdictDiv.innerText = 'Fetching forensic report...';

      // 3. Fetch report details from existing /report-data/<id> route
      const reportRes = await fetch(`http://127.0.0.1:8000/report-data/${report_id}`);
      const reportData = await reportRes.json();

      const summary = reportData.report?.summary || {};
      const score = summary.risk_score !== undefined ? summary.risk_score : (summary.score || 0);

      scoreBadge.innerText = `${score}/10`;

      if (score >= 5.0) {
        scoreBadge.className = 'score-value danger-score';
        verdictDiv.innerText = '⚠️ High Threat Detected';
        verdictDiv.style.color = '#dc2626';
      } else {
        scoreBadge.className = 'score-value safe-score';
        verdictDiv.innerText = '✅ Email Verified Safe';
        verdictDiv.style.color = '#16a34a';
      }

      // Display key findings in the extension UI
      const findings = summary.key_findings || summary.findings || ["Forensic analysis complete."];
      findings.forEach(item => {
        const li = document.createElement('li');
        li.innerText = item;
        indicatorsList.appendChild(li);
      });

    } catch (error) {
      verdictDiv.innerText = 'Network error: Unable to connect to http://127.0.0.1:8000.';
      console.error("Fetch Error:", error);
    }
  };

  chrome.tabs.sendMessage(tab.id, { action: "extract_eml" }, async (response) => {
    if (chrome.runtime.lastError) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ['content.js']
        });

        chrome.tabs.sendMessage(tab.id, { action: "extract_eml" }, async (retryResponse) => {
          if (chrome.runtime.lastError) {
            verdictDiv.innerText = 'Please refresh the Gmail tab (F5) and try again.';
          } else {
            await sendToWebPipeline(retryResponse);
          }
        });
      } catch (err) {
        verdictDiv.innerText = 'Unable to inject content script into active tab.';
      }
    } else {
      await sendToWebPipeline(response);
    }
  });
});
