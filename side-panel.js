document.addEventListener('DOMContentLoaded', () => {
  const scanner = new PrivacyScanner();

  scanner.startScan();

  chrome.tabs.onActivated.addListener(() => {
    setTimeout(() => scanner.startScan(), 300);
  });

  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'complete') {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0] && tabs[0].id === tabId) {
          setTimeout(() => scanner.startScan(), 300);
        }
      });
    }
  });
});
