const HISTORY_KEY = 'dns_history';
const SETTINGS_KEY = 'dnstools_settings';

export const safeStorage = {
  getItem: (key) => {
    try {
      return localStorage.getItem(key);
    } catch (e) {
      console.warn('localStorage.getItem failed:', e);
      return null;
    }
  },
  setItem: (key, value) => {
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      console.warn('localStorage.setItem failed:', e);
      return false;
    }
  },
  removeItem: (key) => {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (e) {
      console.warn('localStorage.removeItem failed:', e);
      return false;
    }
  }
};

export function safeJSONParse(str, fallback){ try { return JSON.parse(str); } catch { return fallback; } }

export function loadSettings() {
  const defaults = {
    providers: ['Google', 'Cloudflare'],
    primaryProvider: 'Google'
  };
  const stored = safeStorage.getItem(SETTINGS_KEY);
  if (!stored) return defaults;
  return { ...defaults, ...safeJSONParse(stored, {}) };
}

export function saveSettings(settings) {
  safeStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}

export function loadHistory(){ 
  try {
    const stored = safeStorage.getItem(HISTORY_KEY);
    if (!stored) return [];
    const parsed = JSON.parse(stored);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.warn('Failed to load history:', e);
    return [];
  }
}

export function saveHistory(arr){ 
  try { 
    safeStorage.setItem(HISTORY_KEY, JSON.stringify(arr.slice(0,100))); 
  } catch(e) { 
    console.warn('history save failed', e); 
  } 
}

export function addHistory(entry){ 
  try {
    const hist = loadHistory(); 
    if (!Array.isArray(hist)) {
      console.warn('History is not an array, resetting');
      saveHistory([entry]);
      return;
    }
    hist.unshift(entry); 
    saveHistory(hist);
    
    // Update last activity timestamp for session tracking
    if (window.dashboardInstance && window.dashboardInstance.updateLastActivity) {
      window.dashboardInstance.updateLastActivity();
    }
  } catch (e) {
    console.warn('Failed to add history entry:', e);
  }
}

export function exportJSON(data, filename='dns_results.json'){ const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'}); const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=filename; a.click(); }

export function presetDomains(){ const params=new URLSearchParams(window.location.search); return params.get('domains')||''; }

export function presetRecordTypes(){ 
  const params=new URLSearchParams(window.location.search); 
  const types = params.get('types');
  return types ? types.split(',').filter(t => t.trim()) : [];
}

export function autoGrow(el){ if(!el) return; el.style.height='auto'; el.style.height = (el.scrollHeight)+'px'; }
