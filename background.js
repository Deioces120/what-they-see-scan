importScripts('domains.js', 'scoring-weights.js');

class PrivacyAnalyzer {
  constructor() {
    this.scanResults = new Map();
    this.networkRequests = new Map();
    this.securityHeaders = new Map();
    this.previousTrackers = new Map();
    this.requestStartTimes = new Map();
    this.MAX_CACHE_SIZE = 50;
    this.MAX_NETWORK_ENTRIES = 500;
    this.privacyDatabase = this.initPrivacyDatabase();
    this.initEventListeners();
    this.initSidePanel();
  }

  initSidePanel() {
    if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
      chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
    }
  }

  initEventListeners() {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => this.analyzeOutgoingRequest(details),
      { urls: ["<all_urls>"] },
      ["requestHeaders"]
    );

    chrome.webRequest.onHeadersReceived.addListener(
      (details) => this.analyzeIncomingResponse(details),
      { urls: ["<all_urls>"] },
      ["responseHeaders"]
    );

    chrome.runtime.onMessage.addListener(
      (request, sender, sendResponse) => {
        this.handleMessage(request, sender, sendResponse);
        return true;
      }
    );

    chrome.webRequest.onCompleted.addListener(
      (details) => this.updateRequestDuration(details),
      { urls: ["<all_urls>"] }
    );

    chrome.tabs.onUpdated.addListener(
      (tabId, changeInfo) => {
        if (changeInfo.status === 'loading') this.cleanupTabData(tabId);
      }
    );

    chrome.tabs.onRemoved.addListener((tabId) => this.cleanupTabData(tabId));
  }

  initPrivacyDatabase() {
    return self.__privacyDomains || {
      trackingDomains: [],
      maliciousDomains: [],
      adNetworks: [],
      socialDomains: [],
      sensitiveDataPatterns: []
    };
  }

  analyzeOutgoingRequest(details) {
    const tabId = details.tabId;
    if (tabId === -1) return;

    if (!this.networkRequests.has(tabId)) {
      this.networkRequests.set(tabId, {
        tracking: [], ads: [], social: [], analytics: [], malicious: [],
        cdn: [], total: 0, domains: new Set(), startTime: Date.now(),
        timeline: [], cookies: [], sensitive: []
      });
    }

    const requests = this.networkRequests.get(tabId);
    requests.total++;

    if (requests.total > this.MAX_NETWORK_ENTRIES) return;

    try {
      const url = new URL(details.url);
      const domain = url.hostname;
      requests.domains.add(domain);

      const requestInfo = {
        domain,
        method: details.method,
        timestamp: Date.now(),
        relativeTime: Date.now() - requests.startTime,
        resourceType: details.type,
        category: this.categorizeDomain(domain),
        url: details.url
      };

      if (this.isTrackingDomain(domain)) requests.tracking.push(requestInfo);
      if (this.isAdNetwork(domain)) requests.ads.push(requestInfo);
      if (this.isSocialNetwork(domain)) requests.social.push(requestInfo);
      if (this.isMaliciousDomain(domain)) requests.malicious.push(requestInfo);
      if (this.isCDN(domain)) requests.cdn.push(requestInfo);

      const analyticsTool = this.detectAnalyticsTool(domain);
      if (analyticsTool) {
        requestInfo.analyticsTool = analyticsTool;
        requests.analytics.push(requestInfo);
      }

      if (this.containsSensitiveData(details.url)) {
        requests.sensitive.push({ domain, url: details.url.substring(0, 200) });
      }

      requests.timeline.push({
        name: details.url,
        type: details.type,
        startTime: requestInfo.relativeTime,
        duration: 0,
        category: requestInfo.category
      });
      this.requestStartTimes.set(details.requestId, { startTime: requestInfo.relativeTime, timelineIdx: requests.timeline.length - 1, tabId });
    } catch (error) {}
  }

  analyzeIncomingResponse(details) {
    const tabId = details.tabId;
    if (tabId === -1) return;

    const headers = details.responseHeaders || [];

    if (details.type === 'main_frame') {
      const securityAnalysis = this.analyzeSecurityHeaders(headers);
      if (!this.securityHeaders.has(tabId)) {
        this.securityHeaders.set(tabId, {});
      }
      this.securityHeaders.get(tabId).main_frame = securityAnalysis;
    }

    this.analyzeCookiesFromHeaders(tabId, headers);
    this.analyzeCSPFromHeaders(tabId, headers);
    this.analyzeHSTSFromHeaders(tabId, headers);
    this.analyzePermissionsPolicyFromHeaders(tabId, headers);
  }

  analyzeCookiesFromHeaders(tabId, headers) {
    headers.forEach(header => {
      if (header.name.toLowerCase() === 'set-cookie') {
        const cookieInfo = this.parseCookie(header.value);
        if (cookieInfo) {
          if (!this.networkRequests.has(tabId)) return;
          const requests = this.networkRequests.get(tabId);
          if (!requests.cookies) requests.cookies = [];
          requests.cookies.push(cookieInfo);
        }
      }
    });
  }

  parseCookie(cookieStr) {
    try {
      const parts = cookieStr.split(';').map(p => p.trim());
      const [nameValue] = parts;
      const [name] = nameValue.split('=');
      const attrs = {};
      parts.slice(1).forEach(p => {
        const [k, v] = p.split('=');
        attrs[k.toLowerCase()] = v || true;
      });
      return {
        name: name.trim(),
        httpOnly: !!attrs.httponly,
        secure: !!attrs.secure,
        sameSite: attrs.samesite || 'none',
        domain: attrs.domain || '',
        path: attrs.path || '/',
        expires: attrs.expires || null
      };
    } catch (e) {
      return null;
    }
  }

  analyzeCSPFromHeaders(tabId, headers) {
    headers.forEach(header => {
      if (header.name.toLowerCase() === 'content-security-policy') {
        if (!this.securityHeaders.has(tabId)) {
          this.securityHeaders.set(tabId, {});
        }
        const existing = this.securityHeaders.get(tabId);
        if (!existing.cspReport) {
          existing.cspReport = this.analyzeCSP(header.value);
        }
      }
    });
  }

  analyzeHSTSFromHeaders(tabId, headers) {
    headers.forEach(header => {
      if (header.name.toLowerCase() === 'strict-transport-security') {
        if (!this.securityHeaders.has(tabId)) {
          this.securityHeaders.set(tabId, {});
        }
        const existing = this.securityHeaders.get(tabId);
        existing.hstsReport = this.analyzeHSTS(header.value);
      }
    });
  }

  analyzePermissionsPolicyFromHeaders(tabId, headers) {
    headers.forEach(header => {
      if (header.name.toLowerCase() === 'permissions-policy' || header.name.toLowerCase() === 'feature-policy') {
        if (!this.securityHeaders.has(tabId)) {
          this.securityHeaders.set(tabId, {});
        }
        const existing = this.securityHeaders.get(tabId);
        existing.permissionsPolicy = header.value;
      }
    });
  }

  analyzeSecurityHeaders(headers) {
    const security = {
      csp: false, cspDetails: null, hsts: false, hstsDetails: null,
      xFrame: false, xContent: false, referrerPolicy: false,
      permissions: false, serverInfo: null, poweredBy: null, securityScore: 0
    };

    headers.forEach(header => {
      const name = header.name.toLowerCase();
      const value = header.value;
      switch (name) {
        case 'content-security-policy':
          security.csp = true;
          security.cspDetails = this.analyzeCSP(value);
          security.securityScore += 25;
          break;
        case 'strict-transport-security':
          security.hsts = true;
          security.hstsDetails = this.analyzeHSTS(value);
          security.securityScore += 20;
          break;
        case 'x-frame-options':
          security.xFrame = true;
          security.securityScore += 15;
          break;
        case 'x-content-type-options':
          security.xContent = true;
          security.securityScore += 10;
          break;
        case 'referrer-policy':
          security.referrerPolicy = true;
          security.securityScore += 10;
          break;
        case 'permissions-policy':
        case 'feature-policy':
          security.permissions = true;
          security.securityScore += 10;
          break;
        case 'server':
          security.serverInfo = value;
          break;
        case 'x-powered-by':
          security.poweredBy = value;
          security.securityScore -= 5;
          break;
      }
    });
    return security;
  }

  analyzeCSP(cspValue) {
    return {
      hasUnsafeInline: cspValue.includes("'unsafe-inline'"),
      hasUnsafeEval: cspValue.includes("'unsafe-eval'"),
      allowsDataUris: cspValue.includes('data:'),
      hasNonce: cspValue.includes('nonce-'),
      hasStrictDynamic: cspValue.includes("'strict-dynamic'"),
      hasReportUri: cspValue.includes('report-uri') || cspValue.includes('report-to'),
      strictness: this.calculateCSPStrictness(cspValue),
      directives: this.parseCSPDirectives(cspValue)
    };
  }

  parseCSPDirectives(csp) {
    const directives = {};
    csp.split(';').forEach(d => {
      const parts = d.trim().split(/\s+/);
      if (parts.length > 0) {
        directives[parts[0]] = parts.slice(1);
      }
    });
    return directives;
  }

  analyzeHSTS(hstsValue) {
    const maxAge = hstsValue.match(/max-age=(\d+)/);
    return {
      maxAge: maxAge ? parseInt(maxAge[1]) : 0,
      includeSubDomains: hstsValue.includes('includeSubDomains'),
      preload: hstsValue.includes('preload')
    };
  }

  calculateCSPStrictness(csp) {
    let s = 5;
    if (csp.includes("'unsafe-inline'")) s -= 2;
    if (csp.includes("'unsafe-eval'")) s -= 2;
    if (csp.includes("'self'")) s += 1;
    if (csp.includes('nonce-')) s += 2;
    if (csp.includes("'strict-dynamic'")) s += 1;
    if (csp.includes("'unsafe-hash'")) s -= 1;
    return Math.max(0, Math.min(10, s));
  }

  handleMessage(request, sender, sendResponse) {
    switch (request.action) {
      case 'getNetworkAnalysis': {
        const tabId = sender.tab?.id || request.tabId;
        const data = this.networkRequests.get(tabId) || {
          tracking: [], ads: [], social: [], analytics: [], malicious: [],
          cdn: [], total: 0, domains: [], timeline: [], cookies: [], sensitive: []
        };
        const serialized = {
          ...data,
          domains: Array.from(data.domains || []),
          cookies: data.cookies || [],
          sensitive: data.sensitive || []
        };
        sendResponse(serialized);
        break;
      }

      case 'performAIAnalysis': {
        const result = this.performRuleBasedAnalysis(request.data);
        sendResponse(result);
        break;
      }

      case 'getSecurityHeaders': {
        const tabId2 = sender.tab?.id || request.tabId;
        sendResponse(this.securityHeaders.get(tabId2) || {});
        break;
      }

      case 'checkNewTrackers': {
        const tabId3 = sender.tab?.id || request.tabId;
        const result = this.checkForNewTrackers(tabId3, request.currentTrackers || []);
        sendResponse(result);
        break;
      }

      default:
        sendResponse({ error: 'Unknown action' });
    }
  }

  checkForNewTrackers(tabId, currentTrackers) {
    const previous = this.previousTrackers.get(tabId) || [];
    const newTrackers = currentTrackers.filter(t => !previous.includes(t));
    this.previousTrackers.set(tabId, currentTrackers);
    if (this.previousTrackers.size > this.MAX_CACHE_SIZE) {
      const firstKey = this.previousTrackers.keys().next().value;
      this.previousTrackers.delete(firstKey);
    }
    return { newTrackers, hasNew: newTrackers.length > 0 };
  }

  performRuleBasedAnalysis(scanData) {
    const privacyScore = this.calculatePrivacyScore(scanData);
    const securityScore = this.calculateSecurityScore(scanData);
    const threats = this.identifyThreats(scanData);
    const recommendations = this.generateRecommendations(scanData, privacyScore, securityScore);
    const dataCollection = this.analyzeDataCollection(scanData);

    return {
      privacyScore,
      securityScore,
      threats,
      recommendations,
      dataCollection,
      riskLevel: this.determineRiskLevel(privacyScore, securityScore, threats)
    };
  }

  calculatePrivacyScore(data) {
    const W = SCORING.privacy;
    let score = W.base;
    const { basic, advanced, network, url } = data;
    try {
      if (network) {
        score += (network.tracking?.length || 0) * W.perTracking;
        score += (network.ads?.length || 0) * W.perAd;
        score += (network.malicious?.length || 0) * W.perMalicious;
        score += Math.max(0, (network.domains?.length || 0) - W.domainThreshold) * W.domainExtra;
        score += (network.sensitive?.length || 0) * W.perSensitive;
      }
      if (advanced) {
        score += (advanced.trackingPixels || 0) * W.perPixel;
        score += (advanced.fingerprintingAttempts || 0) * W.perFingerprint;
        score += (advanced.cryptominers?.length || 0) * W.perMiner;
        if (advanced.deepScanResults) {
          const ds = advanced.deepScanResults;
          const d = W.deepScan;
          score += (ds.cryptocurrency?.miners?.length || 0) * d.cryptoMiners;
          score += (ds.keylogging?.patterns?.length || 0) * d.keylog;
          score += (ds.formjacking?.issues?.length || 0) * d.formjacking;
          score += (ds.magecart?.issues?.length || 0) * d.magecart;
          score += (ds.dataExfil?.patterns?.length || 0) * d.dataExfil;
          score += (ds.xss?.patterns?.length || 0) * d.xss;
          score += (ds.evercookies?.issues?.length || 0) * d.evercookies;
          score += (ds.clipboard?.hasClipboardListeners ? d.clipboard : 0);
          score += (ds.geolocation?.issues?.length || 0) * d.geolocation;
          score += (ds.mediaAccess?.issues?.length || 0) * d.mediaAccess;
          score += (ds.fingerprinting3?.vectors?.filter(v => v.available)?.length || 0) * d.fingerprint3;
          score += (ds.cookieSecurity?.trackingCookies || 0) * d.cookieTrack;
          score += (ds.adInjection?.patterns?.length || 0) * d.adInjection;
          score += (ds.shadowDOM?.count || 0) * d.shadowDOM;
          score += (ds.workerSpam?.workers?.length || 0) * d.workerSpam;
          score += (ds.bluetoothUSB?.issues?.length || 0) * d.bluetoothUSB;
          score += (ds.contacts?.issues?.length > 0 ? d.contacts : 0);
          score += (ds.faceDetection?.issues?.length > 0 ? d.faceDetection : 0);
        }
      }
      if (basic) {
        score += (basic.cookies?.tracking || 0) * 3;
        score += Math.max(0, (basic.scripts?.thirdParty?.length || 0) - 5) * 2;
      }
      score += url?.startsWith('https://') ? W.https.bonus : W.https.penalty;
    } catch (error) {}
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  calculateSecurityScore(data) {
    const W = SCORING.security;
    let score = W.base;
    const { basic, network, url, advanced } = data;
    try {
      score += url?.startsWith('https://') ? W.https.bonus : W.https.penalty;
      if (basic?.security) {
        if (basic.security.csp) score += W.headers.csp;
        if (basic.security.hsts) score += W.headers.hsts;
        if (basic.security.xFrame) score += W.headers.xFrame;
        if (basic.security.xContent) score += W.headers.xContent;
      }
      if (basic?.forms) {
        if (basic.forms.insecure > 0) score += W.forms.insecure;
        if (basic.forms.secure > 0 && basic.forms.insecure === 0) score += W.forms.secure;
      }
      if (network?.malicious?.length > 0) score += network.malicious.length * W.perMalicious;
      if (advanced?.deepScanResults) {
        const ds = advanced.deepScanResults;
        const d = W.deepScan;
        if (ds.csp?.hasCSP) score += d.cspBonus;
        if (ds.mixedContent?.count > 0) score += ds.mixedContent.count * d.mixedContent;
        if (ds.sri?.withoutIntegrity > 5) score += d.sri;
        if (ds.xss?.patterns?.length > 5) score += d.xss;
        if (ds.domVulnerabilities?.patterns?.length > 3) score += d.domVuln;
        if (ds.sessionFixation?.issues?.length > 0) score += d.sessionFixation;
        if (ds.csrf?.issues?.length > 0) score += d.csrf;
        if (ds.openRedirect?.issues?.length > 0) score += d.openRedirect;
        if (ds.keylogging?.patterns?.length > 3) score += d.keylog;
        if (ds.formjacking?.issues?.length > 0) score += d.formjacking;
        if (ds.magecart?.issues?.length > 0) score += d.magecart;
        if (ds.cryptocurrency?.miners?.length > 0) score += d.cryptoMiners;
        if (ds.adInjection?.patterns?.length > 0) score += d.adInjection;
      }
    } catch (error) {}
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  identifyThreats(data) {
    const threats = [];
    const { basic, advanced, network, url } = data;
    try {
      if (!url?.startsWith('https://')) {
        threats.push({
          type: 'insecure_connection', severity: 'critical',
          description: 'Website uses unencrypted HTTP connection',
          recommendation: 'Only enter sensitive information on HTTPS websites',
          category: 'security'
        });
      }
      if (basic?.forms?.insecure > 0) {
        threats.push({
          type: 'insecure_forms', severity: 'high',
          description: `${basic.forms.insecure} form(s) submit data insecurely`,
          recommendation: 'Avoid entering personal information in these forms',
          category: 'security'
        });
      }
      if ((advanced?.fingerprintingAttempts || 0) > 0) {
        threats.push({
          type: 'active_fingerprinting', severity: 'high',
          description: 'Website is actively trying to fingerprint your device',
          recommendation: 'Use privacy-focused browser or incognito mode',
          category: 'privacy'
        });
      }
      if ((basic?.cookies?.tracking || 0) > 10) {
        threats.push({
          type: 'excessive_tracking', severity: 'medium',
          description: 'High number of tracking cookies detected',
          recommendation: 'Clear cookies regularly or use tracking protection',
          category: 'privacy'
        });
      }
      if (network?.malicious?.length > 0) {
        threats.push({
          type: 'malicious_content', severity: 'critical',
          description: 'Connections to known malicious domains detected',
          recommendation: 'Leave this website immediately and run antivirus scan',
          category: 'security'
        });
      }
      if (advanced?.cryptominers?.length > 0) {
        threats.push({
          type: 'cryptomining', severity: 'high',
          description: 'Potential cryptocurrency mining scripts detected',
          recommendation: 'Close this website to prevent unauthorized CPU usage',
          category: 'performance'
        });
      }
      if ((basic?.scripts?.thirdParty?.length || 0) > 20) {
        threats.push({
          type: 'excessive_third_party', severity: 'medium',
          description: `High number of third-party scripts (${basic.scripts.thirdParty.length}) loaded`,
          recommendation: 'Consider using a script blocker to reduce attack surface',
          category: 'privacy'
        });
      }
      if ((advanced?.trackingPixels || 0) > 5) {
        threats.push({
          type: 'tracking_pixels', severity: 'medium',
          description: `Multiple tracking pixels detected (${advanced.trackingPixels})`,
          recommendation: 'This indicates heavy behavioral tracking across the site',
          category: 'privacy'
        });
      }
      if (network?.sensitive?.length > 0) {
        threats.push({
          type: 'sensitive_data_in_url', severity: 'high',
          description: `${network.sensitive.length} request(s) contain sensitive data in URL`,
          recommendation: 'Sensitive data should not be transmitted via URL parameters',
          category: 'security'
        });
      }
      if (advanced?.deepScanResults) {
        const ds = advanced.deepScanResults;
        if (ds.cryptocurrency?.miners?.length > 0) {
          threats.push({
            type: 'deep_cryptomining', severity: 'critical',
            description: `${ds.cryptocurrency.miners.length} cryptocurrency mining script(s) detected`,
            recommendation: 'Close this website immediately - unauthorized mining detected',
            category: 'security'
          });
        }
        if (ds.keylogging?.patterns?.length > 2) {
          threats.push({
            type: 'keylogging', severity: 'critical',
            description: 'Keylogging patterns detected - keystrokes may be monitored',
            recommendation: 'Do not type any sensitive information on this site',
            category: 'security'
          });
        }
        if (ds.formjacking?.issues?.length > 0) {
          threats.push({
            type: 'formjacking', severity: 'critical',
            description: 'Payment form tampering detected',
            recommendation: 'Do not enter payment information on this site',
            category: 'security'
          });
        }
        if (ds.magecart?.issues?.length > 0) {
          threats.push({
            type: 'magecart', severity: 'critical',
            description: 'Magecart-style payment skimming detected',
            recommendation: 'Do not enter payment information - card data may be stolen',
            category: 'security'
          });
        }
        if (ds.xss?.patterns?.length > 3) {
          threats.push({
            type: 'xss_risk', severity: 'high',
            description: `${ds.xss.patterns.length} XSS risk pattern(s) detected`,
            recommendation: 'Use a script blocker to prevent potential code injection',
            category: 'security'
          });
        }
        if (ds.dataExfil?.patterns?.length > 2) {
          threats.push({
            type: 'data_exfiltration', severity: 'high',
            description: 'Data exfiltration patterns detected',
            recommendation: 'Monitor network traffic for unauthorized data transfers',
            category: 'privacy'
          });
        }
        if (ds.openRedirect?.issues?.length > 0) {
          threats.push({
            type: 'open_redirect', severity: 'medium',
            description: 'Open redirect vulnerability detected',
            recommendation: 'Verify redirect URLs carefully before clicking',
            category: 'security'
          });
        }
        if (ds.sqlInjection?.issues?.length > 0) {
          threats.push({
            type: 'sql_injection_pattern', severity: 'low',
            description: 'Suspicious SQL-like keywords found in URL parameters (may be false positive)',
            recommendation: 'This is a pattern match, not a confirmed vulnerability',
            category: 'security'
          });
        }
        if (ds.evercookies?.issues?.length > 0) {
          threats.push({
            type: 'evercookie', severity: 'high',
            description: 'Evercookie persistent tracking detected',
            recommendation: 'Clear all browser data regularly - evercookies are very hard to remove',
            category: 'privacy'
          });
        }
        if (ds.clipboard?.hasClipboardListeners) {
          threats.push({
            type: 'clipboard_monitoring', severity: 'medium',
            description: 'Clipboard access monitoring detected',
            recommendation: 'Avoid copying sensitive data on this site',
            category: 'privacy'
          });
        }
        if (ds.geolocation?.issues?.length > 0) {
          threats.push({
            type: 'geolocation_tracking', severity: 'medium',
            description: 'Geolocation tracking API is active',
            recommendation: 'Deny location permission if prompted',
            category: 'privacy'
          });
        }
        if (ds.mediaAccess?.issues?.length > 0) {
          threats.push({
            type: 'media_access', severity: 'medium',
            description: 'Camera/microphone access API detected',
            recommendation: 'Deny media permissions unless absolutely necessary',
            category: 'privacy'
          });
        }
        if (ds.adInjection?.patterns?.length > 0) {
          threats.push({
            type: 'ad_injection', severity: 'medium',
            description: 'Ad injection patterns detected',
            recommendation: 'Use an ad blocker to prevent unwanted advertisements',
            category: 'privacy'
          });
        }
        if (ds.domVulnerabilities?.patterns?.length > 3) {
          threats.push({
            type: 'dom_vulnerabilities', severity: 'high',
            description: `${ds.domVulnerabilities.patterns.length} DOM-based vulnerability pattern(s) found`,
            recommendation: 'Use a script blocker to prevent potential exploitation',
            category: 'security'
          });
        }
        if (ds.sessionFixation?.issues?.length > 0) {
          threats.push({
            type: 'session_fixation', severity: 'high',
            description: 'Weak session cookie configuration detected',
            recommendation: 'Session may be vulnerable to fixation attacks',
            category: 'security'
          });
        }
        if (ds.fingerprinting3?.vectors?.filter(v => v.available)?.length > 12) {
          threats.push({
            type: 'high_fingerprint_surface', severity: 'medium',
            description: `${ds.fingerprinting3.vectors.filter(v => v.available).length} fingerprinting vectors available`,
            recommendation: 'Use a privacy-focused browser to reduce fingerprinting surface',
            category: 'privacy'
          });
        }
        if (ds.workerSpam?.workers?.length > 3) {
          threats.push({
            type: 'excessive_workers', severity: 'medium',
            description: `${ds.workerSpam.workers.length} web workers detected`,
            recommendation: 'Excessive workers may be used for background tracking or mining',
            category: 'performance'
          });
        }
        if (ds.contacts?.available) {
          threats.push({
            type: 'contacts_api', severity: 'medium',
            description: 'Contacts API available - may request contact access',
            recommendation: 'Deny contacts permission unless necessary',
            category: 'privacy'
          });
        }
        if (ds.faceDetection?.available) {
          threats.push({
            type: 'face_detection', severity: 'medium',
            description: 'Face detection API available',
            recommendation: 'Be cautious of face scanning requests',
            category: 'privacy'
          });
        }
      }
    } catch (error) {}
    return threats;
  }

  generateRecommendations(data, privacyScore, securityScore) {
    const recs = [];
    const { basic, advanced, url, network } = data;
    try {
      if (!url?.startsWith('https://')) {
        recs.push({ priority: 'critical', action: 'Do not enter sensitive information', reason: 'Unencrypted connection - data can be intercepted' });
      }
      if ((advanced?.fingerprintingAttempts || 0) > 0) {
        recs.push({ priority: 'high', action: 'Use incognito/private browsing mode', reason: 'Active device fingerprinting detected - reduces tracking accuracy' });
      }
      if ((basic?.cookies?.tracking || 0) > 8) {
        recs.push({ priority: 'high', action: 'Enable tracking protection in your browser', reason: 'Excessive tracking cookies found on this site' });
      }
      if ((basic?.scripts?.thirdParty?.length || 0) > 15) {
        recs.push({ priority: 'medium', action: 'Install an ad blocker or script blocker', reason: 'Many third-party scripts may compromise privacy and performance' });
      }
      if ((advanced?.trackingPixels || 0) > 3) {
        recs.push({ priority: 'medium', action: 'Consider using a privacy-focused browser', reason: 'Multiple tracking pixels indicate heavy behavioral monitoring' });
      }
      if (securityScore < 50) {
        recs.push({ priority: 'high', action: 'Be cautious with any data you share', reason: 'Low security score - site lacks basic security protections' });
      }
      if (privacyScore < 40) {
        recs.push({ priority: 'high', action: 'Minimize personal information shared on this site', reason: 'Low privacy score - extensive data collection detected' });
      }
      if ((basic?.forms?.password || 0) > 0 && !url?.startsWith('https://')) {
        recs.push({ priority: 'critical', action: 'DO NOT enter passwords on this site', reason: 'Password fields detected on insecure connection' });
      }
      if (network?.sensitive?.length > 0) {
        recs.push({ priority: 'high', action: 'Check for sensitive data in URLs', reason: 'Sensitive data detected in request URLs - may be logged or cached' });
      }
      if (advanced?.deepScanResults) {
        const ds = advanced.deepScanResults;
        if (ds.cryptocurrency?.miners?.length > 0) {
          recs.push({ priority: 'critical', action: 'Close this website immediately', reason: 'Cryptocurrency mining scripts consuming your CPU' });
        }
        if (ds.keylogging?.patterns?.length > 2) {
          recs.push({ priority: 'critical', action: 'Do not type sensitive information', reason: 'Keylogging patterns detected - keystrokes may be monitored' });
        }
        if (ds.formjacking?.issues?.length > 0) {
          recs.push({ priority: 'critical', action: 'Do not enter payment information', reason: 'Payment form tampering detected' });
        }
        if (ds.magecart?.issues?.length > 0) {
          recs.push({ priority: 'critical', action: 'Do not enter payment information', reason: 'Magecart-style payment skimming detected' });
        }
        if (ds.xss?.patterns?.length > 3) {
          recs.push({ priority: 'high', action: 'Use a script blocker', reason: 'Multiple XSS risk patterns found' });
        }
        if (ds.dataExfil?.patterns?.length > 2) {
          recs.push({ priority: 'high', action: 'Monitor network traffic', reason: 'Data exfiltration patterns detected' });
        }
        if (ds.evercookies?.issues?.length > 0) {
          recs.push({ priority: 'high', action: 'Clear all browser data regularly', reason: 'Evercookie persistent tracking detected' });
        }
        if (ds.clipboard?.hasClipboardListeners) {
          recs.push({ priority: 'medium', action: 'Avoid copying sensitive data', reason: 'Clipboard access monitoring detected' });
        }
        if (ds.geolocation?.issues?.length > 0) {
          recs.push({ priority: 'medium', action: 'Deny location permission', reason: 'Geolocation tracking API is active' });
        }
        if (ds.mediaAccess?.issues?.length > 0) {
          recs.push({ priority: 'medium', action: 'Deny camera/microphone permission', reason: 'Media access API detected' });
        }
        if (ds.fingerprinting3?.vectors?.filter(v => v.available)?.length > 12) {
          recs.push({ priority: 'medium', action: 'Use a privacy-focused browser', reason: 'High number of fingerprinting vectors available' });
        }
        if (ds.adInjection?.patterns?.length > 0) {
          recs.push({ priority: 'medium', action: 'Use an ad blocker', reason: 'Ad injection patterns detected' });
        }
        if (ds.shadowDOM?.count > 3) {
          recs.push({ priority: 'low', action: 'Be aware of hidden page elements', reason: 'Multiple Shadow DOM elements may hide tracking code' });
        }
        if (ds.workerSpam?.workers?.length > 3) {
          recs.push({ priority: 'medium', action: 'Monitor CPU usage', reason: 'Excessive web workers detected' });
        }
        if (ds.webAssembly?.available) {
          recs.push({ priority: 'low', action: 'Note: WebAssembly available', reason: 'WebAssembly is available (used by legitimate apps like games, video editors)' });
        }
        if (ds.contacts?.available) {
          recs.push({ priority: 'medium', action: 'Deny contacts permission', reason: 'Contacts API available' });
        }
        if (ds.faceDetection?.available) {
          recs.push({ priority: 'medium', action: 'Be cautious of face scanning', reason: 'Face detection API available' });
        }
      }
      recs.push({ priority: 'low', action: 'Verify website URL matches expected domain', reason: 'General security practice to avoid phishing' });
    } catch (error) {}
    return recs;
  }

  analyzeDataCollection(data) {
    const c = { personal: false, financial: false, behavioral: false, location: false, device: false };
    try {
      const { basic, advanced } = data;
      if (basic?.inputs) {
        if (basic.inputs.email > 0 || basic.inputs.personal > 0) c.personal = true;
        if (basic.inputs.password > 0) c.financial = true;
      }
      if ((basic?.analytics?.tools?.length || 0) > 0 || (basic?.cookies?.tracking || 0) > 0) c.behavioral = true;
      if ((advanced?.fingerprintingAttempts || 0) > 0 || advanced?.webgl) c.device = true;
      if (advanced?.deepScanResults) {
        const ds = advanced.deepScanResults;
        if (ds.geolocation?.issues?.length > 0) c.location = true;
        if (ds.fingerprinting3?.vectors?.filter(v => v.available)?.length > 5) c.device = true;
      }
    } catch (error) {}
    return c;
  }

  determineRiskLevel(privacyScore, securityScore, threats) {
    const critical = threats.filter(t => t.severity === 'critical').length;
    const high = threats.filter(t => t.severity === 'high').length;
    if (critical > 0 || securityScore < 30) return 'critical';
    if (high > 0 || securityScore < 50 || privacyScore < 40) return 'high';
    if (securityScore < 70 || privacyScore < 60) return 'medium';
    return 'low';
  }

  categorizeDomain(domain) {
    const domains = self.__privacyDomains || {};
    if ((domains.analyticsDomains || []).some(d => domain.includes(d))) return 'analytics';
    if ((domains.adNetworks || []).some(d => domain.includes(d))) return 'advertising';
    if ((domains.socialDomains || []).some(d => domain.includes(d))) return 'social';
    if ((domains.essentialDomains || []).some(d => domain.includes(d))) return 'essential';
    return 'unknown';
  }

  isTrackingDomain(domain) {
    return this.privacyDatabase.trackingDomains.some(t => domain.includes(t));
  }

  isAdNetwork(domain) {
    return this.privacyDatabase.adNetworks.some(n => domain.includes(n));
  }

  isSocialNetwork(domain) {
    return this.privacyDatabase.socialDomains.some(s => domain.includes(s));
  }

  isMaliciousDomain(domain) {
    return this.privacyDatabase.maliciousDomains.some(m => domain.includes(m));
  }

  isCDN(domain) {
    const domains = self.__privacyDomains || {};
    return (domains.essentialDomains || []).some(c => domain.includes(c));
  }

  detectAnalyticsTool(domain) {
    const domains = self.__privacyDomains || {};
    const analyticsDomains = domains.analyticsDomains || [];
    if (analyticsDomains.some(d => domain.includes(d))) {
      if (domain.includes('google-analytics') || domain.includes('googletagmanager')) return 'Google Analytics';
      if (domain.includes('facebook')) return 'Facebook Pixel';
      if (domain.includes('hotjar')) return 'Hotjar';
      if (domain.includes('mixpanel')) return 'Mixpanel';
      if (domain.includes('segment')) return 'Segment';
      if (domain.includes('amplitude')) return 'Amplitude';
      if (domain.includes('fullstory')) return 'FullStory';
      if (domain.includes('logrocket')) return 'LogRocket';
      if (domain.includes('heap')) return 'Heap';
      if (domain.includes('pendo')) return 'Pendo';
      if (domain.includes('crazyegg')) return 'CrazyEgg';
      if (domain.includes('mouseflow')) return 'MouseFlow';
      return 'Analytics';
    }
    return null;
  }

  containsSensitiveData(url) {
    try {
      const lower = url.toLowerCase();
      const patterns = self.__privacyDomains?.sensitiveDataPatterns || [];
      return patterns.some(p => lower.includes(p));
    } catch (e) {
      return false;
    }
  }

  updateRequestDuration(details) {
    const startInfo = this.requestStartTimes.get(details.requestId);
    if (!startInfo) return;
    this.requestStartTimes.delete(details.requestId);
    const requests = this.networkRequests.get(startInfo.tabId);
    if (!requests) return;
    const entry = requests.timeline[startInfo.timelineIdx];
    if (entry) {
      entry.duration = Math.max(1, Date.now() - requests.startTime - entry.startTime);
    }
  }

  cleanupTabData(tabId) {
    this.networkRequests.delete(tabId);
    this.securityHeaders.delete(tabId);
    this.scanResults.delete(tabId);
    this.previousTrackers.delete(tabId);
  }
}

const analyzer = new PrivacyAnalyzer();
