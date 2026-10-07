chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan_link",
    title: "Scan link with ScamSentry",
    contexts: ["link"]
  });
  
  chrome.contextMenus.create({
    id: "scan_selection",
    title: "Analyze selected text with ScamSentry",
    contexts: ["selection"]
  });
});

const DASHBOARD_URL = process.env.DASHBOARD_URL || "http://localhost:3000";

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan_link" && info.linkUrl) {
    chrome.tabs.create({
      url: `${DASHBOARD_URL}/?url=${encodeURIComponent(info.linkUrl)}`
    });
  } else if (info.menuItemId === "scan_selection" && info.selectionText) {
    chrome.tabs.create({
      url: `${DASHBOARD_URL}/?text=${encodeURIComponent(info.selectionText)}`
    });
  }
});
