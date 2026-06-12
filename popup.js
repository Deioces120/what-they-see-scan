class PrivacyScanner {
  constructor() {
    this.scanBtn = document.getElementById('scanBtn');
    this.loading = document.getElementById('loading');
    this.results = document.getElementById('results');
    this.tabs = document.getElementById('tabs');
    this.urlBar = document.getElementById('url-bar');
    this.urlDomain = document.getElementById('url-domain');
    this.urlFull = document.getElementById('url-full');
    this.urlLockIcon = document.getElementById('url-lock-icon');
    this.urlStatus = document.getElementById('url-status');
    this.currentTab = null;
    this.scanData = null;
    this.initEventListeners();
  }

  initEventListeners() {
    this.scanBtn.addEventListener('click', () => this.startScan());
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
    });
  }

  switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
  }

  _esc(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  _escAttr(str) {
    return this._esc(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  _extractDomain(url) {
    try {
      return new URL(url).hostname;
    } catch (e) {
      return url;
    }
  }

  _isSecure(url) {
    return url && url.startsWith('https://');
  }

  updateUrlBar(tab) {
    const url = tab.url || '';
    const isSecure = this._isSecure(url);
    const domain = this._extractDomain(url);

    this.urlDomain.textContent = domain;
    this.urlFull.textContent = url;
    this.urlLockIcon.textContent = isSecure ? '\uD83D\uDD12' : '\u26A0\uFE0F';
    this.urlStatus.textContent = isSecure ? 'HTTPS' : 'HTTP';
    this.urlStatus.className = 'url-status ' + (isSecure ? 'secure' : 'insecure');
    this.urlBar.classList.add('active');
  }

  async startScan() {
    try {
      this.scanBtn.textContent = 'Scanning...';
      this.scanBtn.classList.add('scanning');
      this.scanBtn.disabled = true;
      this.loading.style.display = 'block';
      this.results.style.display = 'none';
      this.tabs.classList.add('hidden');

      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentTab = tab;
      this.updateUrlBar(tab);

      const basicScan = await this.performBasicScan(tab);
      const advancedScan = await this.performAdvancedScan(tab);
      const networkAnalysis = await this.analyzeNetworkTraffic(tab);
      const contentScanData = await this.getContentScriptData(tab);
      const permissions = await this.analyzePermissions(tab);

      if (contentScanData) {
        if (contentScanData.trackerCategories) advancedScan.trackerCategories = contentScanData.trackerCategories;
        if (contentScanData.networkTimeline) networkAnalysis.timeline = contentScanData.networkTimeline;
        if (contentScanData.trackingPixels) advancedScan.trackingPixels = (advancedScan.trackingPixels || 0) + contentScanData.trackingPixels.length;
        if (contentScanData.fingerprintingAttempts) advancedScan.fingerprintingAttempts = (advancedScan.fingerprintingAttempts || 0) + contentScanData.fingerprintingAttempts.length;
        if (contentScanData.storage) advancedScan.storage = contentScanData.storage;
        if (contentScanData.vulnerabilities) advancedScan.vulnerabilities = contentScanData.vulnerabilities;
        if (contentScanData.performanceMetrics) advancedScan.performanceMetrics = contentScanData.performanceMetrics;
        if (contentScanData.deepScanResults) advancedScan.deepScanResults = contentScanData.deepScanResults;
        if (contentScanData.cookieDetails) advancedScan.cookieDetails = contentScanData.cookieDetails;
        if (contentScanData.formDetails) advancedScan.formDetails = contentScanData.formDetails;
        if (contentScanData.linkAnalysis) advancedScan.linkAnalysis = contentScanData.linkAnalysis;
      }

      const combinedData = {
        basic: basicScan, advanced: advancedScan, network: networkAnalysis,
        url: tab.url, tabId: tab.id, categories: advancedScan.trackerCategories || {},
        permissions: permissions
      };

      let analysis = await this.performRuleBasedAnalysis(combinedData);

      this.scanData = {
        basic: basicScan, advanced: advancedScan, network: networkAnalysis,
        ai: analysis, url: tab.url, timestamp: new Date().toISOString(),
        categories: advancedScan.trackerCategories || {},
        permissions: permissions
      };

      await this.checkNewTrackers(tab, advancedScan);
      await this.displayResults();
    } catch (error) {
      this.showError(`Scan failed: ${this._esc(error.message)}`);
    } finally {
      this.scanBtn.textContent = 'Start Security Scan';
      this.scanBtn.classList.remove('scanning');
      this.scanBtn.disabled = false;
      this.loading.style.display = 'none';
    }
  }

  async getContentScriptData(tab) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          if (window.__privacyScanner) return window.__privacyScanner.getScanResults();
          return null;
        }
      });
      return results?.[0]?.result || null;
    } catch (e) {
      return null;
    }
  }

  async analyzePermissions(tab) {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'getSecurityHeaders', tabId: tab.id
      });
      return response || {};
    } catch (e) {
      return {};
    }
  }

  async checkNewTrackers(tab, advancedScan) {
    try {
      const allTrackers = [];
      if (advancedScan.trackerCategories) {
        Object.values(advancedScan.trackerCategories).forEach(trackers => {
          if (Array.isArray(trackers)) allTrackers.push(...trackers);
        });
      }
      const response = await chrome.runtime.sendMessage({
        action: 'checkNewTrackers', tabId: tab.id, currentTrackers: allTrackers
      });
      if (response?.hasNew && response.newTrackers.length > 0) {
        this.showTrackerNotification(response.newTrackers);
      }
    } catch (e) {}
  }

  showTrackerNotification(newTrackers) {
    const container = document.querySelector('.container');
    const notification = document.createElement('div');
    notification.className = 'tracker-notification';
    const trackerList = newTrackers.slice(0, 5).map(t => `<div style="padding:2px 0">&bull; ${this._esc(t)}</div>`).join('');
    const moreText = newTrackers.length > 5 ? `<div style="font-style:italic;margin-top:4px;opacity:0.7">+${newTrackers.length - 5} more</div>` : '';
    notification.innerHTML = `
      <div class="notification-header">
        <span>&#128276;</span>
        <strong style="color:#f7b733">New Trackers Detected!</strong>
        <button class="notification-close">&times;</button>
      </div>
      <div class="notification-body">${trackerList}${moreText}</div>
    `;
    notification.querySelector('.notification-close').addEventListener('click', () => notification.remove());
    container.insertBefore(notification, container.firstChild);
  }

  async performBasicScan(tab) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: this.basicWebsiteScan
      });
      return results?.[0]?.result || this.getEmptyBasicScan();
    } catch (error) {
      return this.getEmptyBasicScan();
    }
  }

  async performAdvancedScan(tab) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: this.advancedWebsiteScan
      });
      return results?.[0]?.result || this.getEmptyAdvancedScan();
    } catch (error) {
      return this.getEmptyAdvancedScan();
    }
  }

  async analyzeNetworkTraffic(tab) {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'getNetworkAnalysis', tabId: tab.id
      });
      return response || { tracking: [], ads: [], social: [], analytics: [], total: 0, timeline: [], domains: [] };
    } catch (error) {
      return { tracking: [], ads: [], social: [], analytics: [], total: 0, timeline: [], domains: [] };
    }
  }

  async performRuleBasedAnalysis(scanData) {
    try {
      const response = await chrome.runtime.sendMessage({
        action: 'performAIAnalysis', data: scanData
      });
      return response || this.getEmptyAIAnalysis();
    } catch (error) {
      return this.getEmptyAIAnalysis();
    }
  }

  async displayResults() {
    if (!this.scanData) return;
    const securityScore = this.calculateSecurityScore();
    const grade = this.getScoreGrade(securityScore);

    const ring = document.getElementById('score-ring');
    ring.textContent = securityScore;
    if (securityScore >= 80) ring.style.background = 'rgba(78,205,196,0.3)';
    else if (securityScore >= 60) ring.style.background = 'rgba(247,183,51,0.3)';
    else ring.style.background = 'rgba(255,75,75,0.3)';

    document.getElementById('score-grade').textContent = grade.label;
    document.getElementById('score-grade').style.color = grade.color;

    this.populateOverview(securityScore);
    this.populateSecurity();
    this.populateSSL();
    this.populateHeaders();
    this.populatePrivacy();
    this.populateCookies();
    this.populateThreats();
    this.populateNetwork();
    this.populateFingerprinting();
    this.populateAnalysis();
    this.populateTimeline();
    this.populateRecommendations();
    this.results.style.display = 'block';
    this.tabs.classList.remove('hidden');
  }

  getScoreGrade(score) {
    if (score >= 90) return { letter: 'A+', label: 'A+ - Excellent', color: '#4ecdc4' };
    if (score >= 80) return { letter: 'A', label: 'A - Very Good', color: '#4ecdc4' };
    if (score >= 70) return { letter: 'B', label: 'B - Good', color: '#7eddd4' };
    if (score >= 60) return { letter: 'C', label: 'C - Fair', color: '#f7b733' };
    if (score >= 40) return { letter: 'D', label: 'D - Poor', color: '#ff8a4c' };
    return { letter: 'F', label: 'F - Critical', color: '#ff4b4b' };
  }

  calculateSecurityScore() {
    if (!this.scanData) return 0;
    let score = 50;
    const { basic, advanced, network, url } = this.scanData;
    try {
      if (url?.startsWith('https://')) score += 20; else score -= 30;
      if (basic?.forms) {
        if (basic.forms.secure > 0 && basic.forms.insecure === 0) score += 15;
        else if (basic.forms.insecure > 0) score -= 20;
      }
      if (basic?.scripts?.thirdParty) {
        const count = basic.scripts.thirdParty.length;
        if (count < 5) score += 10; else if (count > 15) score -= 15;
      }
      if (basic?.cookies) {
        if (basic.cookies.tracking < 3) score += 10; else score -= 10;
      }
      if (basic?.security) {
        if (basic.security.csp) score += 15;
        if (basic.security.hsts) score += 10;
        if (basic.security.xFrame) score += 5;
      }
      if (advanced) {
        score -= (advanced.trackingPixels || 0) * 5;
        score -= (advanced.fingerprintingAttempts || 0) * 8;
        score -= (advanced.cryptominers || []).length * 25;
        if (advanced.deepScanResults) {
          const ds = advanced.deepScanResults;
          if (ds.csp?.hasCSP) score += 5;
          if (ds.mixedContent?.count > 0) score -= ds.mixedContent.count * 3;
          if (ds.sri?.withoutIntegrity > 5) score -= 5;
          if (ds.xss?.patterns?.length > 3) score -= 10;
          if (ds.keylogging?.patterns?.length > 2) score -= 15;
          if (ds.formjacking?.issues?.length > 0) score -= 10;
          if (ds.magecart?.issues?.length > 0) score -= 20;
          if (ds.cryptocurrency?.miners?.length > 0) score -= 25;
          if (ds.cookieSecurity?.insecureCookies > 3) score -= 5;
          if (ds.cookieSecurity?.trackingCookies > 5) score -= 5;
          if (ds.domVulnerabilities?.patterns?.length > 3) score -= 8;
          if (ds.dataExfil?.patterns?.length > 2) score -= 10;
          if (ds.adInjection?.patterns?.length > 0) score -= 5;
          if (ds.sessionFixation?.issues?.length > 0) score -= 8;
          if (ds.csrf?.issues?.length > 0) score -= 5;
          if (ds.openRedirect?.issues?.length > 0) score -= 5;
          if (ds.autofill?.issues?.length > 2) score -= 3;
          if (ds.shadowDOM?.count > 3) score -= 3;
          if (ds.webWorkers?.issues?.length > 2) score -= 3;
          if (ds.webAssembly?.available) score -= 2;
          if (ds.fingerprint2?.issues?.length > 0) score -= 5;
          if (ds.canvas2?.attempts > 2) score -= 5;
          if (ds.webgl2?.available) score -= 3;
          if (ds.audio2?.attempts > 2) score -= 5;
          if (ds.font2?.attempts > 2) score -= 3;
          if (ds.screen2?.issues?.length > 0) score -= 3;
          if (ds.navigator2?.issues?.length > 0) score -= 3;
          if (ds.evercookies?.issues?.length > 0) score -= 8;
          if (ds.cacheTiming?.issues?.length > 0) score -= 5;
          if (ds.historySniffing?.issues?.length > 0) score -= 3;
          if (ds.battery?.available) score -= 2;
          if (ds.connection?.available) score -= 1;
          if (ds.speech?.available) score -= 2;
          if (ds.bluetoothUSB?.issues?.length > 0) score -= 2;
          if (ds.mediaAccess?.issues?.length > 0) score -= 2;
          if (ds.geolocation?.issues?.length > 0) score -= 3;
          if (ds.clipboard?.hasClipboardListeners) score -= 3;
          if (ds.permissions?.issues?.length > 0) score -= 2;
          if (ds.webrtc?.available) score -= 2;
          if (ds.serviceWorker?.registered) score -= 1;
          if (ds.nfc?.available) score -= 1;
          if (ds.serial?.available) score -= 1;
          if (ds.usb?.available) score -= 1;
          if (ds.hid?.available) score -= 1;
          if (ds.contacts?.available) score -= 3;
          if (ds.faceDetection?.available) score -= 3;
          if (ds.sensors?.sensors?.length > 0) score -= 2;
          if (ds.workerSpam?.workers?.length > 3) score -= 3;
          if (ds.cryptoMining?.miners?.length > 0) score -= 15;
          if (ds.fingerprinting3?.vectors?.length > 12) score -= 5;
        }
      }
      if (network) {
        score -= (network.tracking || []).length * 3;
        score -= (network.ads || []).length * 2;
      }
    } catch (error) {}
    return Math.max(0, Math.min(100, Math.round(score)));
  }

  populateOverview(score) {
    const content = document.getElementById('overview-content');
    const { basic, network, advanced, deep, ai } = this.scanData;
    const totalTrackers = (network?.tracking?.length || 0) + (basic?.cookies?.tracking || 0);
    const totalThirdParty = (basic?.scripts?.thirdParty?.length || 0) + (network?.ads?.length || 0);
    const totalThreats = (ai?.threats || []).length;
    const totalCookies = deep?.cookieDetails?.length || basic?.cookies?.total || 0;
    const mixedContent = deep?.mixedContent?.length || 0;
    const vulns = (deep?.vulnerabilities?.length || 0) + (advanced?.vulnerabilities?.length || 0);

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128202;</span> Quick Summary</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Network Requests</span><span class="metric-value">${network?.total || 0}</span></div>
          <div class="metric"><span class="metric-label">Third-party Domains</span><span class="metric-value">${totalThirdParty}</span></div>
          <div class="metric"><span class="metric-label">Tracking Elements</span><span class="metric-value">${totalTrackers}</span></div>
          <div class="metric"><span class="metric-label">Forms Detected</span><span class="metric-value">${basic?.forms?.total || 0}</span></div>
          <div class="metric"><span class="metric-label">Cookies</span><span class="metric-value">${totalCookies}</span></div>
          <div class="metric"><span class="metric-label">Security Threats</span><span class="metric-value"><span class="badge ${totalThreats > 5 ? 'badge-red' : totalThreats > 0 ? 'badge-yellow' : 'badge-green'}">${totalThreats}</span></span></div>
          <div class="metric"><span class="metric-label">Mixed Content</span><span class="metric-value"><span class="badge ${mixedContent > 0 ? 'badge-red' : 'badge-green'}">${mixedContent}</span></span></div>
          <div class="metric"><span class="metric-label">Vulnerabilities</span><span class="metric-value"><span class="badge ${vulns > 0 ? 'badge-yellow' : 'badge-green'}">${vulns}</span></span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128200;</span> Threat Overview</div>
        <div class="section-content">
          <div class="chart-row">
            <span class="chart-label">Tracking</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${Math.min(100, (network?.tracking?.length || 0) * 8)}%;background:#ff6b6b"></div></div>
            <span class="chart-count">${network?.tracking?.length || 0}</span>
          </div>
          <div class="chart-row">
            <span class="chart-label">Advertising</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${Math.min(100, (network?.ads?.length || 0) * 10)}%;background:#f7b733"></div></div>
            <span class="chart-count">${network?.ads?.length || 0}</span>
          </div>
          <div class="chart-row">
            <span class="chart-label">Social</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${Math.min(100, (network?.social?.length || 0) * 12)}%;background:#45b7d1"></div></div>
            <span class="chart-count">${network?.social?.length || 0}</span>
          </div>
          <div class="chart-row">
            <span class="chart-label">Analytics</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${Math.min(100, (network?.analytics?.length || 0) * 10)}%;background:#4ecdc4"></div></div>
            <span class="chart-count">${network?.analytics?.length || 0}</span>
          </div>
          <div class="chart-row">
            <span class="chart-label">Fingerprinting</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${Math.min(100, (advanced?.fingerprintingAttempts || 0) * 15)}%;background:#a855f7"></div></div>
            <span class="chart-count">${advanced?.fingerprintingAttempts || 0}</span>
          </div>
          <div class="chart-row">
            <span class="chart-label">Crypto Miners</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${Math.min(100, (advanced?.cryptominers?.length || 0) * 50)}%;background:#ef4444"></div></div>
            <span class="chart-count">${advanced?.cryptominers?.length || 0}</span>
          </div>
        </div>
      </div>
    `;
  }

  _countDeepIssues(ds) {
    let count = 0;
    Object.values(ds).forEach(category => {
      if (category && category.issues) count += category.issues.length;
      if (category && category.miners) count += category.miners.length;
      if (category && category.patterns) count += category.patterns.length;
      if (category && category.issues?.length === undefined) {
        if (Array.isArray(category)) count += category.length;
      }
    });
    return count;
  }

  _countDeepChecks(ds) {
    return Object.keys(ds).length * 10;
  }

  populateSecurity() {
    const content = document.getElementById('security-content');
    const { basic, url, advanced } = this.scanData;
    const isHttps = url?.startsWith('https://');
    const security = basic?.security || {};
    const vulns = advanced?.vulnerabilities || [];
    const ds = advanced?.deepScanResults || {};

    const cspIssues = ds.csp?.issues || [];
    const mixedIssues = ds.mixedContent?.issues || [];
    const sriIssues = ds.sri?.issues || [];
    const xssPatterns = ds.xss?.patterns || [];
    const domIssues = ds.domVulnerabilities?.patterns || [];
    const keylogIssues = ds.keylogging?.patterns || [];
    const formjackIssues = ds.formjacking?.issues || [];
    const magecartIssues = ds.magecart?.issues || [];
    const csrfIssues = ds.csrf?.issues || [];
    const openRedirectIssues = ds.openRedirect?.issues || [];
    const sqliIssues = ds.sqlInjection?.issues || [];

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128274;</span> Connection</div>
        <div class="section-content">
          <div class="alert ${isHttps ? 'alert-success' : 'alert-danger'}">
            <strong>${isHttps ? 'Secure Connection (HTTPS)' : 'Insecure Connection (HTTP)'}</strong>
            ${isHttps ? 'Data transmitted is encrypted.' : 'Data transmitted in plaintext - vulnerable to interception.'}
          </div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128737;&#65039;</span> Security Headers</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Content Security Policy</span><span class="metric-value">${security.csp ? '<span class="badge badge-green">Enabled</span>' : '<span class="badge badge-red">Missing</span>'}</span></div>
          <div class="metric"><span class="metric-label">Strict Transport Security</span><span class="metric-value">${security.hsts ? '<span class="badge badge-green">Enabled</span>' : '<span class="badge badge-red">Missing</span>'}</span></div>
          <div class="metric"><span class="metric-label">X-Frame-Options</span><span class="metric-value">${security.xFrame ? '<span class="badge badge-green">Enabled</span>' : '<span class="badge badge-red">Missing</span>'}</span></div>
          <div class="metric"><span class="metric-label">X-Content-Type-Options</span><span class="metric-value">${security.xContent ? '<span class="badge badge-green">Enabled</span>' : '<span class="badge badge-red">Missing</span>'}</span></div>
          ${cspIssues.length > 0 ? `<div class="alert alert-warning"><strong>CSP Issues</strong>${cspIssues.map(i => `<div>&bull; ${this._esc(i.type)}</div>`).join('')}</div>` : ''}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128203;</span> Form Security</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Secure Forms</span><span class="metric-value"><span class="badge badge-green">${basic?.forms?.secure || 0}</span></span></div>
          <div class="metric"><span class="metric-label">Insecure Forms</span><span class="metric-value"><span class="badge ${(basic?.forms?.insecure || 0) > 0 ? 'badge-red' : 'badge-green'}">${basic?.forms?.insecure || 0}</span></span></div>
          ${formjackIssues.length > 0 ? `<div class="alert alert-danger"><strong>Formjacking Detected</strong>${formjackIssues.map(i => `<div>&bull; ${this._esc(i.type)}</div>`).join('')}</div>` : ''}
          ${csrfIssues.length > 0 ? `<div class="alert alert-warning"><strong>CSRF Protection</strong>${csrfIssues.map(i => `<div>&bull; ${this._esc(i.type)}</div>`).join('')}</div>` : ''}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128269;</span> Input Fields</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Password Fields</span><span class="metric-value">${basic?.inputs?.password || 0}</span></div>
          <div class="metric"><span class="metric-label">Email Fields</span><span class="metric-value">${basic?.inputs?.email || 0}</span></div>
          <div class="metric"><span class="metric-label">Personal Info Fields</span><span class="metric-value">${basic?.inputs?.personal || 0}</span></div>
        </div>
      </div>
      ${mixedIssues.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#9888;&#65039;</span> Mixed Content</div><div class="section-content"><div class="alert alert-danger"><strong>${mixedIssues.length} Mixed Content Issue(s)</strong>${mixedIssues.slice(0, 10).map(i => `<div>&bull; ${this._esc(i.type)}: ${this._esc(i.url?.substring(0, 80))}</div>`).join('')}</div></div></div>` : ''}
      ${sriIssues.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#128274;</span> Subresource Integrity</div><div class="section-content"><div class="alert alert-warning"><strong>SRI Issues</strong>${sriIssues.map(i => `<div>&bull; ${this._esc(i.type)}</div>`).join('')}</div></div></div>` : ''}
      ${xssPatterns.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#128680;</span> XSS Risk Patterns</div><div class="section-content"><div class="alert alert-danger"><strong>${xssPatterns.length} XSS Pattern(s) Detected</strong>${xssPatterns.slice(0, 10).map(p => `<div>&bull; ${this._esc(p)}</div>`).join('')}</div></div></div>` : ''}
      ${domIssues.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#128680;</span> DOM Vulnerabilities</div><div class="section-content"><div class="alert alert-danger"><strong>DOM-based Vulnerabilities</strong>${domIssues.slice(0, 10).map(p => `<div>&bull; ${this._esc(p)}</div>`).join('')}</div></div></div>` : ''}
      ${keylogIssues.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#128680;</span> Keylogging Risk</div><div class="section-content"><div class="alert alert-danger"><strong>Keylogging Patterns Detected</strong>${keylogIssues.slice(0, 10).map(p => `<div>&bull; ${this._esc(p)}</div>`).join('')}</div></div></div>` : ''}
      ${magecartIssues.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#128680;</span> Magecart / Payment Skimming</div><div class="section-content"><div class="alert alert-danger"><strong>Potential Payment Data Theft</strong>${magecartIssues.map(i => `<div>&bull; ${this._esc(i.type)}</div>`).join('')}</div></div></div>` : ''}
      ${openRedirectIssues.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#9888;&#65039;</span> Open Redirect</div><div class="section-content"><div class="alert alert-warning"><strong>Open Redirect Detected</strong>${openRedirectIssues.map(i => `<div>&bull; ${this._esc(i.param)}: ${this._esc(i.value?.substring(0, 80))}</div>`).join('')}</div></div></div>` : ''}
      ${sqliIssues.length > 0 ? `<div class="result-section"><div class="section-title"><span class="icon">&#128680;</span> SQL Injection Patterns</div><div class="section-content"><div class="alert alert-danger"><strong>SQL Injection Patterns in URL</strong>${sqliIssues.map(i => `<div>&bull; ${this._esc(i.param)}: ${this._esc(i.pattern)}</div>`).join('')}</div></div></div>` : ''}
      ${vulns.length > 0 ? `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128680;</span> Vulnerabilities</div>
        <div class="section-content">
          ${vulns.map(v => `<div class="alert ${v.severity === 'high' ? 'alert-danger' : 'alert-warning'}"><strong>${this._esc(v.type.replace(/_/g, ' ').toUpperCase())}</strong>${this._esc(v.detail)}</div>`).join('')}
        </div>
      </div>` : ''}
    `;
  }

  populatePrivacy() {
    const content = document.getElementById('privacy-content');
    const { basic, network, advanced } = this.scanData;
    const analyticsList = (basic?.analytics?.tools || []);
    const storage = advanced?.storage || {};
    const ds = advanced?.deepScanResults || {};

    const storageItems = [];
    if (storage.localStorage) {
      storageItems.push(`<div class="metric"><span class="metric-label">localStorage Items</span><span class="metric-value">${storage.localStorage.items || 0}</span></div>`);
      storageItems.push(`<div class="metric"><span class="metric-label">localStorage Size</span><span class="metric-value">${this.formatBytes(storage.localStorage.totalSize || 0)}</span></div>`);
      if (storage.localStorage.trackingKeys?.length > 0) {
        storageItems.push(`<div class="alert alert-warning" style="margin-top:6px"><strong>Tracking Keys Found</strong>${storage.localStorage.trackingKeys.slice(0, 5).map(k => this._esc(k)).join(', ')}</div>`);
      }
    }
    if (storage.sessionStorage) {
      storageItems.push(`<div class="metric"><span class="metric-label">sessionStorage Items</span><span class="metric-value">${storage.sessionStorage.items || 0}</span></div>`);
    }

    const cookieIssues = ds.cookieSecurity?.issues || [];
    const lsIssues = ds.localStorage?.issues || [];
    const evercookieIssues = ds.evercookies?.issues || [];
    const cacheTimingIssues = ds.cacheTiming?.issues || [];
    const historySniffIssues = ds.historySniffing?.issues || [];
    const cookieSyncIssues = ds.cookieSync?.issues || [];

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#127850;</span> Cookies</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Total Cookies</span><span class="metric-value">${ds.cookieSecurity?.totalCookies || basic?.cookies?.total || 0}</span></div>
          <div class="metric"><span class="metric-label">Tracking Cookies</span><span class="metric-value"><span class="badge ${(ds.cookieSecurity?.trackingCookies || basic?.cookies?.tracking || 0) > 5 ? 'badge-red' : 'badge-green'}">${ds.cookieSecurity?.trackingCookies || basic?.cookies?.tracking || 0}</span></span></div>
          <div class="metric"><span class="metric-label">Third-party Cookies</span><span class="metric-value">${basic?.cookies?.thirdParty || 0}</span></div>
          <div class="metric"><span class="metric-label">Insecure Cookies</span><span class="metric-value"><span class="badge ${(ds.cookieSecurity?.insecureCookies || 0) > 0 ? 'badge-yellow' : 'badge-green'}">${ds.cookieSecurity?.insecureCookies || 0}</span></span></div>
          ${cookieIssues.length > 0 ? `<div class="alert alert-warning" style="margin-top:6px"><strong>Cookie Issues</strong>${cookieIssues.slice(0, 8).map(i => `<div>&bull; ${this._esc(i.type)}${i.cookie ? ': ' + this._esc(i.cookie) : ''}</div>`).join('')}</div>` : ''}
          ${evercookieIssues.length > 0 ? `<div class="alert alert-danger" style="margin-top:6px"><strong>Evercookie Detected</strong>Super-persistent tracking cookies found.</div>` : ''}
          ${cookieSyncIssues.length > 0 ? `<div class="alert alert-warning" style="margin-top:6px"><strong>Cookie Sync</strong>Cross-domain cookie synchronization detected.</div>` : ''}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128202;</span> Analytics & Monitoring</div>
        <div class="section-content">
          ${analyticsList.length > 0 ? analyticsList.map(t => `<div class="alert alert-info" style="margin:4px 0"><strong>&#128200; ${this._esc(t)}</strong></div>`).join('') : '<div class="alert alert-success"><strong>No analytics tools detected</strong></div>'}
          <div class="metric"><span class="metric-label">Analytics Requests</span><span class="metric-value">${network?.analytics?.length || 0}</span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128269;</span> Fingerprinting</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Canvas Fingerprinting</span><span class="metric-value">${advanced?.fingerprintingAttempts || 0} attempts</span></div>
          <div class="metric"><span class="metric-label">WebGL Access</span><span class="metric-value">${advanced?.webgl ? '<span class="badge badge-yellow">Exposed</span>' : '<span class="badge badge-green">Protected</span>'}</span></div>
          ${ds.fingerprint2?.issues?.length > 0 ? `<div class="alert alert-danger" style="margin-top:6px"><strong>FingerprintJS Detected</strong>Advanced fingerprinting library found.</div>` : ''}
          ${ds.canvas2?.attempts > 0 ? `<div class="alert alert-warning" style="margin-top:6px"><strong>Canvas Fingerprinting</strong>${ds.canvas2.attempts} canvas fingerprint attempt(s).</div>` : ''}
          ${ds.audio2?.attempts > 0 ? `<div class="alert alert-warning" style="margin-top:6px"><strong>Audio Fingerprinting</strong>${ds.audio2.attempts} audio fingerprint attempt(s).</div>` : ''}
          ${ds.font2?.attempts > 0 ? `<div class="alert alert-info" style="margin-top:6px"><strong>Font Fingerprinting</strong>${ds.font2.attempts} font detection attempt(s).</div>` : ''}
          ${ds.screen2?.issues?.length > 0 ? `<div class="alert alert-info" style="margin-top:6px"><strong>Screen Fingerprinting</strong>Screen properties accessed for fingerprinting.</div>` : ''}
          ${ds.navigator2?.issues?.length > 0 ? `<div class="alert alert-info" style="margin-top:6px"><strong>Navigator Fingerprinting</strong>Navigator properties accessed for fingerprinting.</div>` : ''}
          ${(advanced?.fingerprintingAttempts || 0) > 0 ? '<div class="alert alert-danger" style="margin-top:6px"><strong>Fingerprinting Detected</strong>This website is trying to uniquely identify your device.</div>' : ''}
          ${ds.fingerprinting3?.vectors?.length > 0 ? `<div class="alert alert-info" style="margin-top:6px"><strong>Fingerprinting Vectors</strong>${ds.fingerprinting3.vectors.filter(v => v.available).length} of ${ds.fingerprinting3.vectors.length} available fingerprinting APIs detected.</div>` : ''}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128190;</span> Browser Storage</div>
        <div class="section-content">
          ${storageItems.join('') || '<div class="alert alert-success"><strong>No storage data found</strong></div>'}
          ${lsIssues.length > 0 ? `<div class="alert alert-warning" style="margin-top:6px"><strong>Storage Issues</strong>${lsIssues.slice(0, 5).map(i => `<div>&bull; ${this._esc(i.type)}</div>`).join('')}</div>` : ''}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128274;</span> Advanced Privacy</div>
        <div class="section-content">
          ${cacheTimingIssues.length > 0 ? `<div class="alert alert-warning"><strong>Cache Timing Attack</strong>Browser history may be probeable.</div>` : ''}
          ${historySniffIssues.length > 0 ? `<div class="alert alert-info"><strong>History Sniffing</strong>Potential browser history detection.</div>` : ''}
          <div class="metric"><span class="metric-label">Plugins</span><span class="metric-value">${ds.plugins?.count || 0}</span></div>
          <div class="metric"><span class="metric-label">MIME Types</span><span class="metric-value">${ds.mimeTypes?.count || 0}</span></div>
          <div class="metric"><span class="metric-label">Shadow DOM Elements</span><span class="metric-value">${ds.shadowDOM?.count || 0}</span></div>
          <div class="metric"><span class="metric-label">Web Workers</span><span class="metric-value">${ds.workerSpam?.workers?.length || 0}</span></div>
          <div class="metric"><span class="metric-label">WebAssembly</span><span class="metric-value">${ds.webAssembly?.available ? '<span class="badge badge-yellow">Available</span>' : '<span class="badge badge-green">Not Used</span>'}</span></div>
          <div class="metric"><span class="metric-label">Service Worker</span><span class="metric-value">${ds.serviceWorker?.registered ? '<span class="badge badge-yellow">Active</span>' : '<span class="badge badge-green">None</span>'}</span></div>
        </div>
      </div>
    `;
  }

  populateThreats() {
    const content = document.getElementById('threats-content');
    const { ai, advanced } = this.scanData;
    const threats = ai?.threats || [];
    const ds = advanced?.deepScanResults || {};

    const allThreats = [...threats];
    if (ds.cryptocurrency?.miners?.length > 0) {
      allThreats.push({ type: 'cryptomining', severity: 'critical', description: `${ds.cryptocurrency.miners.length} cryptocurrency mining script(s) detected`, category: 'security' });
    }
    if (ds.keylogging?.patterns?.length > 2) {
      allThreats.push({ type: 'keylogging', severity: 'critical', description: 'Keylogging patterns detected', category: 'security' });
    }
    if (ds.formjacking?.issues?.length > 0) {
      allThreats.push({ type: 'formjacking', severity: 'critical', description: 'Payment form tampering detected', category: 'security' });
    }
    if (ds.magecart?.issues?.length > 0) {
      allThreats.push({ type: 'magecart', severity: 'critical', description: 'Magecart-style payment skimming detected', category: 'security' });
    }
    if (ds.dataExfil?.patterns?.length > 2) {
      allThreats.push({ type: 'data_exfiltration', severity: 'high', description: 'Data exfiltration patterns detected', category: 'privacy' });
    }
    if (ds.xss?.patterns?.length > 3) {
      allThreats.push({ type: 'xss_risk', severity: 'high', description: 'Multiple XSS risk patterns found', category: 'security' });
    }
    if (ds.openRedirect?.issues?.length > 0) {
      allThreats.push({ type: 'open_redirect', severity: 'medium', description: 'Open redirect vulnerability detected', category: 'security' });
    }
    if (ds.sqlInjection?.issues?.length > 0) {
      allThreats.push({ type: 'sqli_pattern', severity: 'high', description: 'SQL injection patterns in URL', category: 'security' });
    }
    if (ds.evercookies?.issues?.length > 0) {
      allThreats.push({ type: 'evercookie', severity: 'high', description: 'Evercookie persistent tracking detected', category: 'privacy' });
    }
    if (ds.clipboard?.hasClipboardListeners) {
      allThreats.push({ type: 'clipboard_monitoring', severity: 'medium', description: 'Clipboard access monitoring detected', category: 'privacy' });
    }
    if (ds.geolocation?.issues?.length > 0) {
      allThreats.push({ type: 'geolocation_tracking', severity: 'medium', description: 'Geolocation API being used', category: 'privacy' });
    }
    if (ds.mediaAccess?.issues?.length > 0) {
      allThreats.push({ type: 'media_access', severity: 'medium', description: 'Camera/microphone access API detected', category: 'privacy' });
    }
    if (ds.adInjection?.patterns?.length > 0) {
      allThreats.push({ type: 'ad_injection', severity: 'medium', description: 'Ad injection patterns detected', category: 'privacy' });
    }
    if (ds.autofill?.issues?.length > 2) {
      allThreats.push({ type: 'autofill_abuse', severity: 'low', description: 'Potential autofill data harvesting', category: 'privacy' });
    }

    if (allThreats.length === 0) {
      content.innerHTML = '<div class="alert alert-success"><strong>&#9989; No Major Threats Detected</strong>Our deep analysis found no significant security or privacy threats on this website.</div>';
      return;
    }

    const sorted = allThreats.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.severity] || 4) - (order[b.severity] || 4);
    });

    content.innerHTML = sorted.map(threat => {
      const cls = (threat.severity === 'high' || threat.severity === 'critical') ? 'alert-danger' : threat.severity === 'medium' ? 'alert-warning' : 'alert-info';
      const icon = (threat.severity === 'high' || threat.severity === 'critical') ? '&#128680;' : threat.severity === 'medium' ? '&#9888;&#65039;' : '&#8505;&#65039;';
      return `<div class="alert ${cls}">${icon} <strong>${this._esc(threat.type.replace(/_/g, ' ').toUpperCase())}</strong><p style="margin:4px 0">${this._esc(threat.description)}</p>${threat.recommendation ? `<p style="font-size:11px;opacity:0.8"><strong>Fix:</strong> ${this._esc(threat.recommendation)}</p>` : ''}</div>`;
    }).join('');
  }

  populateNetwork() {
    const content = document.getElementById('network-content');
    const { network, basic } = this.scanData;
    const domains = network?.domains || [];
    const uniqueDomains = [...new Set(domains)];

    const categoryColors = {
      tracking: '#ff6b6b', ads: '#f7b733', social: '#45b7d1',
      analytics: '#4ecdc4', cdn: '#96ceb4', unknown: '#636e72'
    };

    const categoryCounts = {
      tracking: network?.tracking?.length || 0,
      ads: network?.ads?.length || 0,
      social: network?.social?.length || 0,
      analytics: network?.analytics?.length || 0,
      cdn: network?.cdn?.length || 0
    };

    const maxCount = Math.max(...Object.values(categoryCounts), 1);

    const domainItems = uniqueDomains.slice(0, 30).map(d => {
      let color = '#636e72';
      let cat = 'unknown';
      if (network?.tracking?.some(t => t.domain === d)) { color = '#ff6b6b'; cat = 'tracking'; }
      else if (network?.ads?.some(a => a.domain === d)) { color = '#f7b733'; cat = 'ads'; }
      else if (network?.social?.some(s => s.domain === d)) { color = '#45b7d1'; cat = 'social'; }
      else if (network?.analytics?.some(a => a.domain === d)) { color = '#4ecdc4'; cat = 'analytics'; }
      return `<div class="domain-item"><span class="domain-dot" style="background:${color}"></span><span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${this._esc(d)}</span><span class="badge badge-gray">${cat}</span></div>`;
    }).join('');

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#127760;</span> Domain Summary</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Total Requests</span><span class="metric-value">${network?.total || 0}</span></div>
          <div class="metric"><span class="metric-label">Unique Domains</span><span class="metric-value">${uniqueDomains.length}</span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128202;</span> Request Categories</div>
        <div class="section-content">
          ${Object.entries(categoryCounts).map(([cat, count]) => `
            <div class="chart-row">
              <span class="chart-label">${cat}</span>
              <div class="chart-bar"><div class="chart-fill" style="width:${(count / maxCount) * 100}%;background:${categoryColors[cat]}"></div></div>
              <span class="chart-count">${count}</span>
            </div>
          `).join('')}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128203;</span> Connected Domains</div>
        <div class="section-content domain-list">${domainItems}${uniqueDomains.length > 30 ? `<div class="alert alert-info" style="margin-top:6px">+${uniqueDomains.length - 30} more domains</div>` : ''}</div>
      </div>
    `;
  }

  populateAnalysis() {
    const content = document.getElementById('analysis-content');
    const { ai, basic, network, advanced } = this.scanData;
    const privacyScore = ai?.privacyScore || 50;
    const riskLevel = ai?.riskLevel || 'unknown';
    const dataCollection = ai?.dataCollection || {};
    const grade = this.getScoreGrade(privacyScore);
    const ds = advanced?.deepScanResults || {};

    const riskColors = { low: '#4ecdc4', medium: '#f7b733', high: '#ff8a4c', critical: '#ff4b4b', unknown: '#636e72' };

    const deepChecks = [
      { name: 'CSP Analysis', result: ds.csp, icon: '&#128274;' },
      { name: 'Mixed Content', result: ds.mixedContent, icon: '&#9888;&#65039;' },
      { name: 'SRI Check', result: ds.sri, icon: '&#128274;' },
      { name: 'XSS Patterns', result: ds.xss, icon: '&#128680;' },
      { name: 'Clickjacking', result: ds.clickjacking, icon: '&#128737;&#65039;' },
      { name: 'Cookie Security', result: ds.cookieSecurity, icon: '&#127850;' },
      { name: 'LocalStorage', result: ds.localStorage, icon: '&#128190;' },
      { name: 'DOM Vulnerabilities', result: ds.domVulnerabilities, icon: '&#128680;' },
      { name: 'Keylogging', result: ds.keylogging, icon: '&#128680;' },
      { name: 'Formjacking', result: ds.formjacking, icon: '&#128680;' },
      { name: 'Magecart', result: ds.magecart, icon: '&#128680;' },
      { name: 'CSRF', result: ds.csrf, icon: '&#128274;' },
      { name: 'Open Redirect', result: ds.openRedirect, icon: '&#9888;&#65039;' },
      { name: 'SQL Injection', result: ds.sqlInjection, icon: '&#128680;' },
      { name: 'Cryptomining', result: ds.cryptocurrency, icon: '&#128680;' },
      { name: 'Clipboard', result: ds.clipboard, icon: '&#128203;' },
      { name: 'Geolocation', result: ds.geolocation, icon: '&#127757;' },
      { name: 'Media Access', result: ds.mediaAccess, icon: '&#127909;' },
      { name: 'Notifications', result: ds.notifications, icon: '&#128276;' },
      { name: 'WebRTC', result: ds.webrtc, icon: '&#128225;' },
      { name: 'Service Worker', result: ds.serviceWorker, icon: '&#9881;&#65039;' },
      { name: 'WebAssembly', result: ds.webAssembly, icon: '&#9881;&#65039;' },
      { name: 'Web Workers', result: ds.webWorkers, icon: '&#9881;&#65039;' },
      { name: 'Shadow DOM', result: ds.shadowDOM, icon: '&#128065;' },
      { name: 'DNS Prefetch', result: ds.dnsPrefetch, icon: '&#127760;' },
      { name: 'Preconnect', result: ds.preconnect, icon: '&#127760;' },
      { name: 'External Fonts', result: ds.externalFonts, icon: '&#9998;&#65039;' },
      { name: 'Iframe Sandbox', result: ds.iframeSandbox, icon: '&#128737;&#65039;' },
      { name: 'Data Exfiltration', result: ds.dataExfil, icon: '&#128680;' },
      { name: 'Ad Injection', result: ds.adInjection, icon: '&#128680;' },
      { name: 'Fingerprinting', result: ds.fingerprinting3, icon: '&#128269;' },
      { name: 'Battery API', result: ds.battery, icon: '&#128267;' },
      { name: 'Connection API', result: ds.connection, icon: '&#128246;' },
      { name: 'Web Bluetooth', result: ds.bluetoothUSB, icon: '&#128266;' },
      { name: 'NFC', result: ds.nfc, icon: '&#128246;' },
      { name: 'Serial API', result: ds.serial, icon: '&#128266;' },
      { name: 'USB Device', result: ds.usb, icon: '&#128266;' },
      { name: 'HID', result: ds.hid, icon: '&#128266;' },
      { name: 'Speech', result: ds.speech, icon: '&#127908;' },
      { name: 'VR/AR', result: ds.vr, icon: '&#127918;' },
      { name: 'Gamepad', result: ds.gamepad, icon: '&#127918;' },
      { name: 'Sensors', result: ds.sensors, icon: '&#128225;' },
      { name: 'Permissions', result: ds.permissions, icon: '&#128272;' },
      { name: 'Credentials', result: ds.credentials, icon: '&#128272;' },
      { name: 'Contacts', result: ds.contacts, icon: '&#128100;' },
      { name: 'Face Detection', result: ds.faceDetection, icon: '&#128064;' },
      { name: 'Media Devices', result: ds.mediaDevices, icon: '&#127909;' },
      { name: 'Web Share', result: ds.shareAPI, icon: '&#128228;' },
      { name: 'Payment API', result: ds.paymentAPIs, icon: '&#128179;' },
      { name: 'Storage API', result: ds.storageAPI, icon: '&#128190;' },
      { name: 'IndexedDB', result: ds.indexedDB, icon: '&#128190;' },
      { name: 'Evercookies', result: ds.evercookies, icon: '&#127850;' },
      { name: 'Cache Timing', result: ds.cacheTiming, icon: '&#9201;' },
      { name: 'History Sniffing', result: ds.historySniffing, icon: '&#128214;' },
      { name: 'Timer Abuse', result: ds.timers, icon: '&#9201;' },
      { name: 'Worker Spam', result: ds.workerSpam, icon: '&#9881;&#65039;' },
      { name: 'Crypto Mining', result: ds.cryptoMining, icon: '&#128680;' },
      { name: 'Affiliate Tracking', result: ds.affiliate, icon: '&#128200;' }
    ];

    const passedChecks = deepChecks.filter(c => {
      const r = c.result;
      if (!r) return true;
      return (!r.issues || r.issues.length === 0) && (!r.miners || r.miners.length === 0) && (!r.patterns || r.patterns.length === 0);
    }).length;
    const failedChecks = deepChecks.length - passedChecks;

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128202;</span> Privacy Score</div>
        <div class="section-content">
          <div style="display:flex;align-items:center;gap:16px;margin-bottom:12px">
            <div class="score-ring" style="width:60px;height:60px;font-size:22px;background:${riskColors[riskLevel] || '#636e72'}30">${privacyScore}</div>
            <div>
              <div style="font-size:16px;font-weight:700;color:${grade.color}">${grade.letter}</div>
              <div style="font-size:12px;color:rgba(255,255,255,0.5)">${grade.label}</div>
            </div>
          </div>
          <div class="alert ${riskLevel === 'low' ? 'alert-success' : riskLevel === 'medium' ? 'alert-warning' : 'alert-danger'}">
            <strong>Risk Level: ${riskLevel.toUpperCase()}</strong>
          </div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128202;</span> Data Collection</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Personal Data</span><span class="metric-value">${dataCollection.personal ? '<span class="badge badge-red">Collected</span>' : '<span class="badge badge-green">None</span>'}</span></div>
          <div class="metric"><span class="metric-label">Financial Data</span><span class="metric-value">${dataCollection.financial ? '<span class="badge badge-red">Collected</span>' : '<span class="badge badge-green">None</span>'}</span></div>
          <div class="metric"><span class="metric-label">Behavioral Tracking</span><span class="metric-value">${dataCollection.behavioral ? '<span class="badge badge-yellow">Active</span>' : '<span class="badge badge-green">None</span>'}</span></div>
          <div class="metric"><span class="metric-label">Location Data</span><span class="metric-value">${dataCollection.location ? '<span class="badge badge-red">Possible</span>' : '<span class="badge badge-green">None</span>'}</span></div>
          <div class="metric"><span class="metric-label">Device Fingerprinting</span><span class="metric-value">${dataCollection.device ? '<span class="badge badge-red">Active</span>' : '<span class="badge badge-green">None</span>'}</span></div>
          <div class="metric"><span class="metric-label">Social Tracking</span><span class="metric-value">${dataCollection.social ? '<span class="badge badge-yellow">Active</span>' : '<span class="badge badge-green">None</span>'}</span></div>
          <div class="metric"><span class="metric-label">Contact Data</span><span class="metric-value">${dataCollection.contact ? '<span class="badge badge-red">Collected</span>' : '<span class="badge badge-green">None</span>'}</span></div>
          <div class="metric"><span class="metric-label">Browsing History</span><span class="metric-value">${dataCollection.browsing ? '<span class="badge badge-yellow">Tracked</span>' : '<span class="badge badge-green">None</span>'}</span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128269;</span> Deep Scan Results</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Total Checks Performed</span><span class="metric-value">${deepChecks.length}</span></div>
          <div class="metric"><span class="metric-label">Checks Passed</span><span class="metric-value"><span class="badge badge-green">${passedChecks}</span></span></div>
          <div class="metric"><span class="metric-label">Issues Found</span><span class="metric-value"><span class="badge ${failedChecks > 10 ? 'badge-red' : failedChecks > 5 ? 'badge-yellow' : 'badge-green'}">${failedChecks}</span></span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128202;</span> Detailed Check Results</div>
        <div class="section-content">
          ${deepChecks.map(check => {
            const r = check.result;
            const hasIssues = r && ((r.issues && r.issues.length > 0) || (r.miners && r.miners.length > 0) || (r.patterns && r.patterns.length > 0));
            return `<div class="metric"><span class="metric-label">${check.icon} ${check.name}</span><span class="metric-value"><span class="badge ${hasIssues ? 'badge-red' : 'badge-green'}">${hasIssues ? (r.issues?.length || r.miners?.length || r.patterns?.length || 0) + ' issues' : 'Passed'}</span></span></div>`;
          }).join('')}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128269;</span> Technical Details</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Network Requests</span><span class="metric-value">${network?.total || 0}</span></div>
          <div class="metric"><span class="metric-label">Third-party Domains</span><span class="metric-value">${[...new Set(basic?.scripts?.thirdParty || [])].length}</span></div>
          <div class="metric"><span class="metric-label">Scan Time</span><span class="metric-value">${this._esc(new Date(this.scanData.timestamp).toLocaleTimeString())}</span></div>
        </div>
      </div>
    `;
  }

  populateTimeline() {
    const content = document.getElementById('timeline-content');
    const { network } = this.scanData;
    const timeline = network?.timeline || [];
    if (timeline.length === 0) {
      content.innerHTML = '<div class="alert alert-info">No network timing data available for this scan.</div>';
      return;
    }
    const sorted = [...timeline].sort((a, b) => a.startTime - b.startTime);
    const maxTime = Math.max(...sorted.map(r => r.startTime + r.duration), 1);
    const categoryColors = { analytics: '#4ecdc4', advertising: '#ff6b6b', social: '#45b7d1', essential: '#96ceb4', unknown: '#636e72' };
    const categoryCounts = {};
    sorted.forEach(r => { const cat = r.category || 'unknown'; categoryCounts[cat] = (categoryCounts[cat] || 0) + 1; });
    const legendItems = Object.entries(categoryCounts).map(([cat, count]) =>
      `<span class="legend-item"><span class="legend-dot" style="background:${categoryColors[cat] || '#636e72'}"></span>${this._esc(cat)} (${count})</span>`
    ).join('');
    const bars = sorted.slice(0, 60).map(r => {
      const left = (r.startTime / maxTime) * 100;
      const width = Math.max(1, (r.duration / maxTime) * 100);
      const color = categoryColors[r.category] || '#636e72';
      const hostname = (() => { try { return new URL(r.name).hostname; } catch(e) { return ''; } })();
      return `<div class="timeline-bar" style="left:${left}%;width:${width}%;background:${color}" title="${this._escAttr(hostname)} (${this._escAttr(r.type)}) - ${r.startTime}ms"></div>`;
    }).join('');
    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#9201;</span> Request Timeline</div>
        <div class="timeline-legend">${legendItems}</div>
        <div class="timeline-bar-container">${bars}</div>
        <div class="timeline-labels"><span>0ms</span><span>${Math.round(maxTime / 2)}ms</span><span>${Math.round(maxTime)}ms</span></div>
      </div>
    `;
  }

  populateRecommendations() {
    const content = document.getElementById('recs-content');
    const { ai, advanced } = this.scanData;
    const recs = ai?.recommendations || [];
    const ds = advanced?.deepScanResults || {};

    const icons = {
      critical: '&#128680;', high: '&#9888;&#65039;', medium: '&#128161;', low: '&#9989;'
    };
    const colors = {
      critical: '#ff4b4b', high: '#ff8a4c', medium: '#f7b733', low: '#4ecdc4'
    };

    const allRecs = [...recs];
    if (ds.cryptocurrency?.miners?.length > 0) {
      allRecs.push({ priority: 'critical', action: 'Close this website immediately', reason: 'Cryptocurrency mining scripts consuming your CPU' });
    }
    if (ds.keylogging?.patterns?.length > 2) {
      allRecs.push({ priority: 'critical', action: 'Do not type sensitive information', reason: 'Keylogging patterns detected - your keystrokes may be monitored' });
    }
    if (ds.formjacking?.issues?.length > 0) {
      allRecs.push({ priority: 'critical', action: 'Do not enter payment information', reason: 'Payment form tampering detected - your card data may be stolen' });
    }
    if (ds.magecart?.issues?.length > 0) {
      allRecs.push({ priority: 'critical', action: 'Do not enter payment information', reason: 'Magecart-style payment skimming detected' });
    }
    if (ds.xss?.patterns?.length > 3) {
      allRecs.push({ priority: 'high', action: 'Use a script blocker', reason: 'Multiple XSS risk patterns found - potential code injection vectors' });
    }
    if (ds.dataExfil?.patterns?.length > 2) {
      allRecs.push({ priority: 'high', action: 'Monitor network traffic', reason: 'Data exfiltration patterns detected' });
    }
    if (ds.openRedirect?.issues?.length > 0) {
      allRecs.push({ priority: 'medium', action: 'Verify redirect URLs carefully', reason: 'Open redirect vulnerability detected' });
    }
    if (ds.evercookies?.issues?.length > 0) {
      allRecs.push({ priority: 'high', action: 'Clear all browser data regularly', reason: 'Evercookie persistent tracking detected - very hard to remove' });
    }
    if (ds.clipboard?.hasClipboardListeners) {
      allRecs.push({ priority: 'medium', action: 'Avoid copying sensitive data on this site', reason: 'Clipboard access monitoring detected' });
    }
    if (ds.geolocation?.issues?.length > 0) {
      allRecs.push({ priority: 'medium', action: 'Deny location permission if prompted', reason: 'Geolocation tracking API is active' });
    }
    if (ds.mediaAccess?.issues?.length > 0) {
      allRecs.push({ priority: 'medium', action: 'Deny camera/microphone permission', reason: 'Media access API detected on this page' });
    }
    if (ds.adInjection?.patterns?.length > 0) {
      allRecs.push({ priority: 'medium', action: 'Use an ad blocker', reason: 'Ad injection patterns detected' });
    }
    if (ds.cookieSecurity?.trackingCookies > 5) {
      allRecs.push({ priority: 'medium', action: 'Clear cookies after visiting', reason: 'Excessive tracking cookies found' });
    }
    if (ds.fingerprinting3?.vectors?.filter(v => v.available)?.length > 12) {
      allRecs.push({ priority: 'medium', action: 'Use a privacy-focused browser', reason: 'High number of fingerprinting vectors available' });
    }
    if (ds.domVulnerabilities?.patterns?.length > 3) {
      allRecs.push({ priority: 'high', action: 'Use a script blocker', reason: 'DOM-based vulnerabilities detected' });
    }
    if (ds.shadowDOM?.count > 3) {
      allRecs.push({ priority: 'low', action: 'Be aware of hidden page elements', reason: 'Multiple Shadow DOM elements may hide tracking code' });
    }
    if (ds.workerSpam?.workers?.length > 3) {
      allRecs.push({ priority: 'medium', action: 'Monitor CPU usage', reason: 'Excessive web workers may be used for background tracking' });
    }
    if (ds.webAssembly?.available) {
      allRecs.push({ priority: 'low', action: 'Monitor CPU usage', reason: 'WebAssembly available - could be used for cryptomining' });
    }

    if (allRecs.length === 0) {
      content.innerHTML = '<div class="alert alert-success"><strong>&#9989; All Good!</strong>No specific recommendations at this time. This site appears to have good security practices.</div>';
      return;
    }

    const sorted = allRecs.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[a.priority] || 4) - (order[b.priority] || 4);
    });

    content.innerHTML = sorted.map(rec => {
      const color = colors[rec.priority] || '#636e72';
      const icon = icons[rec.priority] || '&#128161;';
      return `<div class="rec-item" style="border-left:3px solid ${color}">
        <div class="rec-icon">${icon}</div>
        <div class="rec-content">
          <div class="rec-title" style="color:${color}">${this._esc(rec.action)}</div>
          <div class="rec-desc">${this._esc(rec.reason)}</div>
        </div>
      </div>`;
    }).join('');
  }

  async performDeepScan(tab) {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: this.deepSecurityScan
      });
      return results?.[0]?.result || this.getEmptyDeepScan();
    } catch (error) {
      return this.getEmptyDeepScan();
    }
  }

  populateSSL() {
    const content = document.getElementById('ssl-content');
    const { deep, url, permissions } = this.scanData;
    const ssl = deep?.ssl || {};
    const secHeaders = permissions?.main_frame || {};
    const isHttps = url?.startsWith('https://');

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128274;</span> SSL/TLS Analysis</div>
        <div class="section-content">
          <div class="alert ${isHttps ? 'alert-success' : 'alert-danger'}">
            <strong>${isHttps ? 'Valid SSL/TLS Connection' : 'No SSL/TLS Connection'}</strong>
            ${isHttps ? 'Connection is encrypted and verified.' : 'No encryption detected - data can be intercepted.'}
          </div>
          <div class="metric"><span class="metric-label">Protocol</span><span class="metric-value">${isHttps ? 'HTTPS' : 'HTTP'}</span></div>
          <div class="metric"><span class="metric-label">Secure Connection</span><span class="metric-value"><span class="badge ${isHttps ? 'badge-green' : 'badge-red'}">${isHttps ? 'Yes' : 'No'}</span></span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128737;&#65039;</span> HSTS Details</div>
        <div class="section-content">
          ${secHeaders.hsts ? `
            <div class="alert alert-success"><strong>HSTS Enabled</strong>Strict-Transport-Security header is present.</div>
            <div class="metric"><span class="metric-label">max-age</span><span class="metric-value">${secHeaders.hstsDetails?.maxAge || 'N/A'} seconds</span></div>
            <div class="metric"><span class="metric-label">includeSubDomains</span><span class="metric-value">${secHeaders.hstsDetails?.includeSubDomains ? 'Yes' : 'No'}</span></div>
            <div class="metric"><span class="metric-label">preload</span><span class="metric-value">${secHeaders.hstsDetails?.preload ? 'Yes' : 'No'}</span></div>
          ` : '<div class="alert alert-danger"><strong>HSTS Not Enabled</strong>Site does not enforce HTTPS via HSTS header.</div>'}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128200;</span> SSL Security Assessment</div>
        <div class="section-content">
          <div class="chart-row">
            <span class="chart-label">Encryption</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${isHttps ? 100 : 0}%;background:${isHttps ? '#4ecdc4' : '#ff4b4b'}"></div></div>
            <span class="chart-count">${isHttps ? 'OK' : 'FAIL'}</span>
          </div>
          <div class="chart-row">
            <span class="chart-label">HSTS</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${secHeaders.hsts ? 100 : 0}%;background:${secHeaders.hsts ? '#4ecdc4' : '#ff4b4b'}"></div></div>
            <span class="chart-count">${secHeaders.hsts ? 'OK' : 'FAIL'}</span>
          </div>
          <div class="chart-row">
            <span class="chart-label">Certificate</span>
            <div class="chart-bar"><div class="chart-fill" style="width:${isHttps ? 100 : 0}%;background:${isHttps ? '#4ecdc4' : '#ff4b4b'}"></div></div>
            <span class="chart-count">${isHttps ? 'OK' : 'FAIL'}</span>
          </div>
        </div>
      </div>
    `;
  }

  populateHeaders() {
    const content = document.getElementById('headers-content');
    const { permissions } = this.scanData;
    const secHeaders = permissions?.main_frame || {};

    const headersList = [
      { name: 'Content-Security-Policy', present: secHeaders.csp, details: secHeaders.cspDetails, good: true },
      { name: 'Strict-Transport-Security', present: secHeaders.hsts, details: secHeaders.hstsDetails, good: true },
      { name: 'X-Frame-Options', present: secHeaders.xFrame, details: null, good: true },
      { name: 'X-Content-Type-Options', present: secHeaders.xContent, details: null, good: true },
      { name: 'Referrer-Policy', present: secHeaders.referrerPolicy, details: null, good: true },
      { name: 'Permissions-Policy', present: secHeaders.permissions, details: null, good: true },
      { name: 'X-Powered-By', present: !!secHeaders.poweredBy, details: secHeaders.poweredBy, good: false },
      { name: 'Server', present: !!secHeaders.serverInfo, details: secHeaders.serverInfo, good: false }
    ];

    const presentCount = headersList.filter(h => h.present && h.good).length;
    const totalGoodHeaders = headersList.filter(h => h.good).length;
    const score = Math.round((presentCount / totalGoodHeaders) * 100);

    let cspDetailsHtml = '';
    if (secHeaders.cspDetails) {
      const d = secHeaders.cspDetails;
      cspDetailsHtml = `
        <div class="result-section">
          <div class="section-title"><span class="icon">&#128196;</span> CSP Analysis</div>
          <div class="section-content">
            <div class="metric"><span class="metric-label">unsafe-inline</span><span class="metric-value"><span class="badge ${d.hasUnsafeInline ? 'badge-red' : 'badge-green'}">${d.hasUnsafeInline ? 'Present (Weak)' : 'Not Present'}</span></span></div>
            <div class="metric"><span class="metric-label">unsafe-eval</span><span class="metric-value"><span class="badge ${d.hasUnsafeEval ? 'badge-red' : 'badge-green'}">${d.hasUnsafeEval ? 'Present (Dangerous)' : 'Not Present'}</span></span></div>
            <div class="metric"><span class="metric-label">data: URIs</span><span class="metric-value"><span class="badge ${d.allowsDataUris ? 'badge-yellow' : 'badge-green'}">${d.allowsDataUris ? 'Allowed' : 'Blocked'}</span></span></div>
            <div class="metric"><span class="metric-label">Nonce-based</span><span class="metric-value"><span class="badge ${d.hasNonce ? 'badge-green' : 'badge-gray'}">${d.hasNonce ? 'Yes' : 'No'}</span></span></div>
            <div class="metric"><span class="metric-label">Strictness Score</span><span class="metric-value">${d.strictness}/10</span></div>
          </div>
        </div>
      `;
    }

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128737;&#65039;</span> Security Headers Score: ${score}%</div>
        <div class="section-content">
          <div class="chart-bar" style="margin-bottom:12px"><div class="chart-fill" style="width:${score}%;background:${score >= 70 ? '#4ecdc4' : score >= 40 ? '#f7b733' : '#ff4b4b'}"></div></div>
          ${headersList.map(h => `
            <div class="metric">
              <span class="metric-label">${h.name}</span>
              <span class="metric-value">
                ${h.present ?
                  (h.good ? '<span class="badge badge-green">Present</span>' : `<span class="badge badge-yellow">Exposed: ${this._esc(h.details)}</span>`) :
                  '<span class="badge badge-red">Missing</span>'}
              </span>
            </div>
          `).join('')}
        </div>
      </div>
      ${cspDetailsHtml}
    `;
  }

  populateCookies() {
    const content = document.getElementById('cookies-content');
    const { basic, deep } = this.scanData;
    const cookies = deep?.cookieDetails || [];
    const cookieSummary = basic?.cookies || {};

    let cookieTableHtml = '';
    if (cookies.length > 0) {
      cookieTableHtml = `
        <table class="cookie-table">
          <thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Tracking</th></tr></thead>
          <tbody>
            ${cookies.slice(0, 30).map(c => `
              <tr>
                <td style="max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${this._escAttr(c.name)}">${this._esc(c.name)}</td>
                <td>${c.secure ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-red">No</span>'}</td>
                <td>${c.httpOnly ? '<span class="badge badge-green">Yes</span>' : '<span class="badge badge-red">No</span>'}</td>
                <td><span class="badge badge-gray">${c.sameSite || 'None'}</span></td>
                <td>${c.hasTrackingPattern ? '<span class="badge badge-red">Yes</span>' : '<span class="badge badge-green">No</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        ${cookies.length > 30 ? `<div class="alert alert-info" style="margin-top:8px">+${cookies.length - 30} more cookies</div>` : ''}
      `;
    }

    const insecureCookies = cookies.filter(c => !c.secure).length;
    const noHttpOnly = cookies.filter(c => !c.httpOnly).length;
    const noSameSite = cookies.filter(c => !c.sameSite || c.sameSite === 'none').length;

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#127850;</span> Cookie Summary</div>
        <div class="section-content">
          <div class="metric"><span class="metric-label">Total Cookies</span><span class="metric-value">${cookieSummary.total || 0}</span></div>
          <div class="metric"><span class="metric-label">Tracking Cookies</span><span class="metric-value"><span class="badge ${(cookieSummary.tracking || 0) > 5 ? 'badge-red' : 'badge-green'}">${cookieSummary.tracking || 0}</span></span></div>
          <div class="metric"><span class="metric-label">Third-party Cookies</span><span class="metric-value">${cookieSummary.thirdParty || 0}</span></div>
          <div class="metric"><span class="metric-label">Insecure (No Secure flag)</span><span class="metric-value"><span class="badge ${insecureCookies > 0 ? 'badge-red' : 'badge-green'}">${insecureCookies}</span></span></div>
          <div class="metric"><span class="metric-label">JS-accessible (No HttpOnly)</span><span class="metric-value"><span class="badge ${noHttpOnly > 0 ? 'badge-yellow' : 'badge-green'}">${noHttpOnly}</span></span></div>
          <div class="metric"><span class="metric-label">No SameSite Policy</span><span class="metric-value"><span class="badge ${noSameSite > 0 ? 'badge-yellow' : 'badge-green'}">${noSameSite}</span></span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128203;</span> Cookie Details</div>
        <div class="section-content">
          ${cookieTableHtml || '<div class="alert alert-success"><strong>No cookies found</strong></div>'}
        </div>
      </div>
    `;
  }

  populateFingerprinting() {
    const content = document.getElementById('fingerprinting-content');
    const { deep, advanced } = this.scanData;
    const fp = deep?.fingerprintingDetails || {};
    const fpAttempts = advanced?.fingerprintingAttempts || 0;
    const webgl = advanced?.webgl || deep?.webgl;

    content.innerHTML = `
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128270;</span> Fingerprinting Detection</div>
        <div class="section-content">
          <div class="alert ${fpAttempts > 0 ? 'alert-danger' : 'alert-success'}">
            <strong>${fpAttempts > 0 ? 'Fingerprinting Detected (' + fpAttempts + ' attempts)' : 'No Fingerprinting Detected'}</strong>
            ${fpAttempts > 0 ? 'This site is trying to uniquely identify your device.' : 'No device fingerprinting techniques detected.'}
          </div>
          <div class="metric"><span class="metric-label">Canvas Fingerprinting</span><span class="metric-value">${fp.canvas || 0} calls</span></div>
          <div class="metric"><span class="metric-label">WebGL Fingerprinting</span><span class="metric-value">${fp.webgl || 0} calls</span></div>
          <div class="metric"><span class="metric-label">Audio Fingerprinting</span><span class="metric-value">${fp.audio || 0} calls</span></div>
          <div class="metric"><span class="metric-label">Font Detection</span><span class="metric-value">${fp.fonts || 0} attempts</span></div>
          <div class="metric"><span class="metric-label">Navigator Enumeration</span><span class="metric-value">${fp.navigator || 0} calls</span></div>
          <div class="metric"><span class="metric-label">Screen Enumeration</span><span class="metric-value">${fp.screen || 0} calls</span></div>
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128187;</span> WebGL Information</div>
        <div class="section-content">
          ${webgl ? `
            <div class="alert alert-warning"><strong>WebGL Exposed</strong>WebGL information can be used for fingerprinting.</div>
            <div class="metric"><span class="metric-label">Vendor</span><span class="metric-value">${this._esc(webgl.vendor || 'N/A')}</span></div>
            <div class="metric"><span class="metric-label">Renderer</span><span class="metric-value">${this._esc(webgl.renderer || 'N/A')}</span></div>
            <div class="metric"><span class="metric-label">Version</span><span class="metric-value">${this._esc(webgl.version || 'N/A')}</span></div>
            <div class="metric"><span class="metric-label">Extensions</span><span class="metric-value">${webgl.extensions || 0}</span></div>
          ` : '<div class="alert alert-success"><strong>WebGL Not Exposed</strong></div>'}
        </div>
      </div>
      <div class="result-section">
        <div class="section-title"><span class="icon">&#128200;</span> Fingerprinting Risk</div>
        <div class="section-content">
          <div class="chart-bar" style="margin-bottom:8px"><div class="chart-fill" style="width:${Math.min(100, fpAttempts * 20)}%;background:${fpAttempts > 3 ? '#ff4b4b' : fpAttempts > 0 ? '#f7b733' : '#4ecdc4'}"></div></div>
          <div class="metric"><span class="metric-label">Total Fingerprinting Signals</span><span class="metric-value">${fpAttempts}</span></div>
          <div class="metric"><span class="metric-label">Risk Level</span><span class="metric-value"><span class="badge ${fpAttempts > 3 ? 'badge-red' : fpAttempts > 0 ? 'badge-yellow' : 'badge-green'}">${fpAttempts > 3 ? 'HIGH' : fpAttempts > 0 ? 'MEDIUM' : 'LOW'}</span></span></div>
        </div>
      </div>
    `;
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  showError(message) {
    this.results.innerHTML = `<div class="alert alert-danger"><strong>&#10060; Scan Error</strong><pre style="white-space:pre-wrap;margin-top:10px;font-size:12px">${message}</pre><div style="margin-top:10px"><button id="retryBtn" style="padding:6px 12px;background:#e94560;color:white;border:none;border-radius:6px;cursor:pointer">Retry</button></div></div>`;
    this.results.style.display = 'block';
    this.tabs.classList.add('hidden');
    document.getElementById('retryBtn')?.addEventListener('click', () => location.reload());
  }

  getEmptyBasicScan() {
    return { forms: { total: 0, secure: 0, insecure: 0 }, scripts: { total: 0, thirdParty: [], inline: 0 }, cookies: { total: 0, tracking: 0, thirdParty: 0 }, analytics: { tools: [] }, security: { csp: false, xFrame: false, hsts: false, xContent: false }, inputs: { password: 0, email: 0, personal: 0 } };
  }

  getEmptyAdvancedScan() {
    return { trackingPixels: 0, socialWidgets: 0, fingerprintingAttempts: 0, webgl: null, cryptominers: [], adNetworks: [], trackerCategories: {}, storage: null, vulnerabilities: [], performanceMetrics: {}, deepScanResults: {} };
  }

  getEmptyAIAnalysis() {
    return { privacyScore: 50, threats: [], recommendations: [], dataCollection: { personal: false, financial: false, behavioral: false, location: false, device: false }, riskLevel: 'unknown' };
  }

  getEmptyDeepScan() {
    return { cookieDetails: [], fingerprintingDetails: { canvas: 0, webgl: 0, audio: 0, fonts: 0, navigator: 0, screen: 0 }, vulnerabilities: [], mixedContent: [], forms: [], links: {}, metaTags: [], webgl: null };
  }

  basicWebsiteScan() {
    const results = { forms: { total: 0, secure: 0, insecure: 0 }, scripts: { total: 0, thirdParty: [], inline: 0 }, cookies: { total: 0, tracking: 0, thirdParty: 0 }, analytics: { tools: [] }, security: { csp: false, xFrame: false, hsts: false, xContent: false }, inputs: { password: 0, email: 0, personal: 0 } };
    try {
      const forms = document.querySelectorAll('form');
      results.forms.total = forms.length;
      forms.forEach(form => {
        const action = form.action || window.location.href;
        if (action.startsWith('https://') || action.startsWith('/') || !action) results.forms.secure++;
        else results.forms.insecure++;
      });
      const scripts = document.scripts;
      results.scripts.total = scripts.length;
      Array.from(scripts).forEach(script => {
        if (script.src) {
          try {
            const scriptUrl = new URL(script.src, window.location.href);
            if (scriptUrl.hostname !== window.location.hostname) results.scripts.thirdParty.push(scriptUrl.hostname);
          } catch (e) { results.scripts.inline++; }
        } else { results.scripts.inline++; }
      });
      results.scripts.thirdParty = [...new Set(results.scripts.thirdParty)];
      const cookies = document.cookie.split(';').filter(c => c.trim());
      results.cookies.total = cookies.length;
      const tp = ['_ga', '_gid', '_gat', '_gtag', '_fbp', '_fbc', '_hjid', 'utm_', '_clck', '_pk_'];
      cookies.forEach(c => { const n = c.split('=')[0].trim(); if (tp.some(p => n.includes(p))) results.cookies.tracking++; });
      results.cookies.thirdParty = Math.min(results.cookies.total, Math.floor(results.scripts.thirdParty.length * 0.7));
      const ad = { 'Google Analytics': () => window.gtag || window.ga || window.dataLayer || document.querySelector('script[src*="google-analytics"]') || document.querySelector('script[src*="googletagmanager"]'), 'Facebook Pixel': () => window.fbq || document.querySelector('script[src*="facebook.net"]'), 'Hotjar': () => window.hj || document.querySelector('script[src*="hotjar"]'), 'Mixpanel': () => window.mixpanel || document.querySelector('script[src*="mixpanel"]') };
      Object.entries(ad).forEach(([n, d]) => { try { if (d()) results.analytics.tools.push(n); } catch (e) {} });
      document.querySelectorAll('meta[http-equiv]').forEach(m => { if (m.getAttribute('http-equiv').toLowerCase() === 'content-security-policy') results.security.csp = true; });
      results.security.hsts = document.location.protocol === 'https:';
      document.querySelectorAll('input, textarea').forEach(input => {
        const type = (input.type || '').toLowerCase();
        const name = (input.name || '').toLowerCase();
        const ph = (input.placeholder || '').toLowerCase();
        const id = (input.id || '').toLowerCase();
        if (type === 'password') results.inputs.password++;
        if (type === 'email' || name.includes('email') || ph.includes('email') || id.includes('email')) results.inputs.email++;
        if (name.includes('phone') || name.includes('address') || name.includes('name') || ph.includes('phone') || ph.includes('address') || ph.includes('name') || id.includes('phone') || id.includes('address')) results.inputs.personal++;
      });
    } catch (error) {}
    return results;
  }

  advancedWebsiteScan() {
    const results = { trackingPixels: 0, socialWidgets: 0, fingerprintingAttempts: 0, webgl: null, cryptominers: [], adNetworks: [], storage: null, vulnerabilities: [], performanceMetrics: {}, trackerCategories: { analytics: [], advertising: [], social: [], essential: [], unknown: [] } };
    try {
      document.querySelectorAll('img').forEach(img => {
        if ((img.width <= 1 && img.height <= 1) || (img.style.width === '1px' && img.style.height === '1px') || img.style.display === 'none' || img.style.visibility === 'hidden') results.trackingPixels++;
      });
      document.querySelectorAll('iframe').forEach(iframe => {
        const w = parseInt(iframe.width) || iframe.offsetWidth;
        const h = parseInt(iframe.height) || iframe.offsetHeight;
        if ((w <= 1 && h <= 1) && iframe.src) results.trackingPixels++;
      });
      ['iframe[src*="facebook.com"]', 'iframe[src*="twitter.com"]', 'iframe[src*="instagram.com"]', 'iframe[src*="linkedin.com"]', 'iframe[src*="youtube.com"]', '.fb-like', '.twitter-share-button'].forEach(s => { try { results.socialWidgets += document.querySelectorAll(s).length; } catch (e) {} });
      try {
        const c = document.createElement('canvas');
        const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (gl) results.webgl = { renderer: gl.getParameter(gl.RENDERER), vendor: gl.getParameter(gl.VENDOR), version: gl.getParameter(gl.VERSION) };
      } catch (e) {}
      const adNets = ['googlesyndication.com', 'doubleclick.net', 'googleadservices.com', 'amazon-adsystem.com', 'outbrain.com', 'taboola.com', 'criteo.com', 'media.net', 'pubmatic.com', 'rubiconproject.com', 'openx.net', 'adnxs.com', 'moatads.com', 'quantserve.com', 'scorecardresearch.com', 'bluekai.com', 'bidswitch.net', 'demdex.net', 'rlcdn.com', 'adsrvr.org', 'mathtag.com', 'turn.com', 'spotxchange.com', 'sharethrough.com', 'teads.tv', 'prebid.org'];
      document.querySelectorAll('script[src]').forEach(s => { adNets.forEach(n => { if (s.src.includes(n) && !results.adNetworks.includes(n)) results.adNetworks.push(n); }); });
      const mp = ['coinhive', 'jsecoin', 'coinerra', 'minergate', 'crypto-loot', 'webminerpool', 'coin-have', 'minero', 'coinimp', 'authedmine', 'cryptaloot', 'webminepool', 'monerominer', 'cryptojack'];
      document.querySelectorAll('script').forEach(s => { const c = (s.textContent || s.src || '').toLowerCase(); mp.forEach(p => { if (c.includes(p)) results.cryptominers.push({ type: 'potential_cryptominer', pattern: p, source: s.src || 'inline' }); }); });

      const formVulns = [];
      document.querySelectorAll('form').forEach(form => {
        const action = form.action || '';
        if (action && !action.startsWith('https://') && !action.startsWith('/') && action !== window.location.href) {
          formVulns.push({ type: 'insecure_form_action', severity: 'high', detail: 'Form action URL is not HTTPS' });
        }
        if (form.method && form.method.toLowerCase() === 'get' && form.querySelector('input[type="password"]')) {
          formVulns.push({ type: 'password_in_get_form', severity: 'critical', detail: 'Password field in GET form' });
        }
      });
      let evalCount = 0;
      let documentWriteCount = 0;
      document.querySelectorAll('script:not([src])').forEach(script => {
        const content = script.textContent || '';
        if (content.includes('eval(')) evalCount++;
        if (content.includes('document.write(')) documentWriteCount++;
      });
      if (evalCount > 0) formVulns.push({ type: 'eval_usage', severity: 'high', detail: evalCount + ' inline script(s) use eval()' });
      if (documentWriteCount > 0) formVulns.push({ type: 'document_write', severity: 'medium', detail: documentWriteCount + ' inline script(s) use document.write()' });

      document.querySelectorAll('script[src], link[href], iframe[src], img[src]').forEach(el => {
        const src = el.src || el.href || '';
        try {
          const url = new URL(src);
          if (url.protocol === 'http:' && window.location.protocol === 'https:') {
            formVulns.push({ type: 'mixed_content', severity: el.tagName === 'SCRIPT' ? 'high' : 'medium', detail: 'HTTP resource on HTTPS page: ' + src.substring(0, 80) });
          }
        } catch (e) {}
      });
      results.vulnerabilities = formVulns;

      try {
        const storage = { localStorage: { items: 0, trackingKeys: [], totalSize: 0 }, sessionStorage: { items: 0, trackingKeys: [], totalSize: 0 } };
        const trackingPatterns = ['_ga', '_gid', '_gat', '_fbp', '_fbc', '_hjid', '__utma', 'utm_', '_clck', '_pk_', '_uetsid', '_uetvid', 'NID', '1P_JAR', 'SID', 'HSID', 'SSID', 'APISID', 'SAPISID'];
        try {
          const data = { ...localStorage };
          storage.localStorage.items = Object.keys(data).length;
          storage.localStorage.trackingKeys = Object.keys(data).filter(k => trackingPatterns.some(p => k.toLowerCase().includes(p)));
          storage.localStorage.totalSize = JSON.stringify(data).length;
        } catch (e) {}
        try {
          const data = { ...sessionStorage };
          storage.sessionStorage.items = Object.keys(data).length;
          storage.sessionStorage.trackingKeys = Object.keys(data).filter(k => trackingPatterns.some(p => k.toLowerCase().includes(p)));
          storage.sessionStorage.totalSize = JSON.stringify(data).length;
        } catch (e) {}
        results.storage = storage;
      } catch (e) {}

      try {
        if (window.performance && window.performance.timing) {
          const t = window.performance.timing;
          results.performanceMetrics = {
            dns: t.domainLookupEnd - t.domainLookupStart,
            tcp: t.connectEnd - t.connectStart,
            ttfb: t.responseStart - t.navigationStart,
            domReady: t.domContentLoadedEventEnd - t.navigationStart,
            load: t.loadEventEnd - t.navigationStart
          };
        }
        if (window.performance && window.performance.getEntriesByType) {
          const resources = window.performance.getEntriesByType('resource');
          results.performanceMetrics.totalResources = resources.length;
          results.performanceMetrics.slowResources = resources.filter(r => r.duration > 1000).length;
          results.performanceMetrics.largeResources = resources.filter(r => r.transferSize > 500000).length;
          results.performanceMetrics.totalTransferSize = resources.reduce((sum, r) => sum + (r.transferSize || 0), 0);
          results.performanceMetrics.resourceTypes = {};
          resources.forEach(r => {
            const type = r.initiatorType || 'other';
            results.performanceMetrics.resourceTypes[type] = (results.performanceMetrics.resourceTypes[type] || 0) + 1;
          });
        }
      } catch (e) {}

      const allDomains = new Set();
      document.querySelectorAll('script[src], link[href], iframe[src], img[src]').forEach(el => {
        const src = el.src || el.href || '';
        try { allDomains.add(new URL(src, window.location.href).hostname); } catch (e) {}
      });
      const catDefs = {
        analytics: ['google-analytics.com','googletagmanager.com','hotjar.com','mixpanel.com','amplitude.com','segment.com','fullstory.com','crazyegg.com','newrelic.com','sentry.io','datadoghq.com','bugsnag.com','pendo.io','heap.io'],
        advertising: ['googlesyndication.com','doubleclick.net','googleadservices.com','amazon-adsystem.com','outbrain.com','taboola.com','criteo.com','media.net','pubmatic.com','rubiconproject.com','openx.net','adnxs.com','moatads.com','demdex.net','adsrvr.org'],
        social: ['facebook.com','facebook.net','fbcdn.net','instagram.com','twitter.com','t.co','linkedin.com','licdn.com','pinterest.com','pinimg.com','tiktok.com','youtube.com','youtu.be','ytimg.com'],
        essential: ['cloudflare.com','amazonaws.com','cloudfront.net','jsdelivr.net','unpkg.com','cdnjs.cloudflare.com','googleapis.com','gstatic.com','github.io','azure.com','fastly.net'],
        fingerprinting: ['fingerprint.com','fpjs.io'],
        malware: ['coinhive.com','coin-hive.com','authedmine.com','crypto-loot.com','webminerpool.com','jsecoin.com','minergate.com','deepminer.net','coinimp.com']
      };
      allDomains.forEach(domain => {
        let categorized = false;
        for (const [cat, patterns] of Object.entries(catDefs)) {
          if (patterns.some(p => domain.includes(p))) {
            results.trackerCategories[cat] = results.trackerCategories[cat] || [];
            if (!results.trackerCategories[cat].includes(domain)) results.trackerCategories[cat].push(domain);
            categorized = true;
            break;
          }
        }
        if (!categorized) results.trackerCategories.unknown.push(domain);
      });

    } catch (error) {}
    return results;
  }

  deepSecurityScan() {
    const result = {
      cookieDetails: [], fingerprintingDetails: { canvas: 0, webgl: 0, audio: 0, fonts: 0, navigator: 0, screen: 0 },
      vulnerabilities: [], mixedContent: [], forms: [], links: {}, metaTags: [], webgl: null
    };
    try {
      const currentHost = window.location.hostname;
      const isHTTPS = window.location.protocol === 'https:';

      document.cookie.split(';').forEach(c => {
        if (!c.trim()) return;
        const parts = c.split('=');
        const name = parts[0].trim();
        result.cookieDetails.push({
          name, secure: c.includes('Secure'), httpOnly: c.includes('HttpOnly'),
          sameSite: (c.match(/SameSite=([^;]+)/i) || [])[1] || null,
          hasTrackingPattern: ['_ga','_gid','_gat','_fbp','_fbc','_hjid','__utma','utm_','_clck','_pk_','_uetsid','_uetvid','NID','1P_JAR','SID','HSID','SSID','APISID','SAPISID'].some(p => name.includes(p))
        });
      });

      if (window.__privacyScanner) {
        const fp = window.__privacyScanner.fingerprintingAttempts || [];
        fp.forEach(f => {
          if (f.type === 'canvas_toDataURL' || f.type === 'canvas_getImageData') result.fingerprintingDetails.canvas++;
          else if (f.type === 'webgl_context_creation') result.fingerprintingDetails.webgl++;
          else if (f.type === 'audio_oscillator' || f.type === 'audio_analyser') result.fingerprintingDetails.audio++;
          else if (f.type === 'font_detection_style') result.fingerprintingDetails.fonts++;
        });
        if (window.__privacyScanner.webglInfo) result.webgl = window.__privacyScanner.webglInfo;
      }

      document.querySelectorAll('img, script, iframe, link, video, audio, source, embed, object').forEach(el => {
        const src = el.src || el.href || el.data || '';
        if (!src) return;
        if (isHTTPS && src.startsWith('http://')) {
          result.mixedContent.push({ type: el.tagName.toLowerCase(), url: src.substring(0, 120), severity: el.tagName === 'SCRIPT' ? 'high' : 'medium' });
        }
      });

      document.querySelectorAll('form').forEach(form => {
        const inputs = [];
        form.querySelectorAll('input, textarea, select').forEach(input => {
          inputs.push({ type: input.type || 'text', name: input.name || '', required: input.required, autocomplete: input.getAttribute('autocomplete') || '' });
        });
        result.forms.push({
          action: form.action || window.location.href,
          method: (form.method || 'get').toUpperCase(),
          target: form.target || '_self',
          enctype: form.enctype || 'application/x-www-form-urlencoded',
          fields: inputs,
          hasCSRFToken: !!form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[type="hidden"][name*="csrf"]'),
          isHTTPS: (form.action || window.location.href).startsWith('https://')
        });
      });

      const linkPatterns = { external: 0, internal: 0, mailto: 0, tel: 0, javascript: 0, suspicious: 0 };
      document.querySelectorAll('a[href]').forEach(a => {
        const href = a.href;
        try {
          if (href.startsWith('mailto:')) linkPatterns.mailto++;
          else if (href.startsWith('tel:')) linkPatterns.tel++;
          else if (href.startsWith('javascript:')) linkPatterns.javascript++;
          else {
            const url = new URL(href, window.location.href);
            if (url.hostname === currentHost) linkPatterns.internal++;
            else {
              linkPatterns.external++;
              if (['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly'].some(s => url.hostname.includes(s))) linkPatterns.suspicious++;
            }
          }
        } catch (e) {}
      });
      result.links = linkPatterns;

      document.querySelectorAll('meta').forEach(meta => {
        const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
        const content = meta.getAttribute('content') || '';
        if (name) result.metaTags.push({ name: name.toLowerCase(), content: content.substring(0, 200) });
      });

      try {
        const canvas = document.createElement('canvas');
        canvas.width = 200; canvas.height = 50;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.textBaseline = 'top';
          ctx.font = '14px Arial';
          ctx.fillStyle = '#f60';
          ctx.fillRect(125, 1, 62, 20);
          ctx.fillStyle = '#069';
          ctx.fillText('fingerprint', 2, 15);
          ctx.fillStyle = 'rgba(102,204,0,0.7)';
          ctx.fillText('fingerprint', 4, 17);
          const dataUrl = canvas.toDataURL();
          if (dataUrl && dataUrl.length > 100) result.fingerprintingDetails.canvas = (result.fingerprintingDetails.canvas || 0) + 1;
        }
      } catch (e) {}

      try {
        const navProps = ['userAgent','platform','language','languages','hardwareConcurrency','deviceMemory','maxTouchPoints','cookieEnabled','doNotTrack','vendor','vendorSub','productSub','webdriver'];
        result.fingerprintingDetails.navigator = navProps.filter(p => { try { return typeof navigator[p] !== 'undefined'; } catch(e) { return false; } }).length;
      } catch (e) {}

      try {
        const screenProps = ['width','height','availWidth','availHeight','colorDepth','pixelDepth'];
        result.fingerprintingDetails.screen = screenProps.filter(p => { try { return typeof screen[p] !== 'undefined'; } catch(e) { return false; } }).length;
      } catch (e) {}

      try {
        const testFonts = ['Arial','Verdana','Times New Roman','Courier New','Georgia','Palatino','Garamond','Comic Sans MS','Impact','Lucida Console','Tahoma','Trebuchet MS','Calibri','Cambria','Segoe UI','Helvetica'];
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (ctx) {
          const baseline = {};
          testFonts.forEach(font => {
            ctx.font = "12px '" + font + "', monospace";
            const m = ctx.measureText('mmmmmmmmmmlli');
            baseline[font] = { width: m.width, height: (m.actualBoundingBoxAscent || 0) + (m.actualBoundingBoxDescent || 0) };
          });
          const unique = new Set(Object.values(baseline).map(v => Math.round(v.width) + '-' + Math.round(v.height)));
          if (unique.size > 1) result.fingerprintingDetails.fonts = unique.size;
        }
      } catch (e) {}

      const suspiciousPatterns = [
        { pattern: /eval\s*\(/g, type: 'eval_usage', severity: 'high' },
        { pattern: /document\.write\s*\(/g, type: 'document_write', severity: 'medium' },
        { pattern: /innerHTML\s*=/g, type: 'innerHTML_assignment', severity: 'medium' },
        { pattern: /outerHTML\s*=/g, type: 'outerHTML_assignment', severity: 'medium' },
        { pattern: /XMLHttpRequest/g, type: 'xhr_usage', severity: 'low' },
        { pattern: /fetch\s*\(/g, type: 'fetch_usage', severity: 'low' },
        { pattern: /WebSocket/g, type: 'websocket_usage', severity: 'low' },
        { pattern: /navigator\.sendBeacon/g, type: 'beacon_usage', severity: 'medium' },
        { pattern: /ServiceWorker/g, type: 'service_worker', severity: 'low' },
        { pattern: /IndexedDB/g, type: 'indexed_db', severity: 'low' },
        { pattern: /Notification\.requestPermission/g, type: 'notification_request', severity: 'medium' },
        { pattern: /geolocation/gi, type: 'geolocation_access', severity: 'high' },
        { pattern: /getUserMedia/g, type: 'camera_mic_access', severity: 'high' },
        { pattern: /clipboard\.(read|write)/g, type: 'clipboard_access', severity: 'high' },
        { pattern: /localStorage/g, type: 'localStorage_access', severity: 'low' },
        { pattern: /sessionStorage/g, type: 'sessionStorage_access', severity: 'low' },
        { pattern: /postMessage/g, type: 'postMessage_usage', severity: 'low' },
        { pattern: /Function\s*\(/g, type: 'dynamic_function', severity: 'high' },
        { pattern: /setTimeout\s*\(\s*['"]/g, type: 'setTimeout_string', severity: 'high' },
        { pattern: /setInterval\s*\(\s*['"]/g, type: 'setInterval_string', severity: 'high' },
        { pattern: /atob\s*\(/g, type: 'base64_decode', severity: 'medium' },
        { pattern: /String\.fromCharCode/g, type: 'string_fromCharCode', severity: 'medium' },
        { pattern: /RegExp\s*\(/g, type: 'dynamic_regexp', severity: 'medium' }
      ];

      const vulnCounts = {};
      document.querySelectorAll('script:not([src])').forEach(script => {
        const text = script.textContent || '';
        if (text.length > 10000) return;
        suspiciousPatterns.forEach(({ pattern, type, severity }) => {
          const matches = text.match(pattern);
          if (matches) {
            if (!vulnCounts[type]) vulnCounts[type] = { count: 0, severity, examples: [] };
            vulnCounts[type].count += matches.length;
            if (vulnCounts[type].examples.length < 2) {
              const idx = text.indexOf(matches[0]);
              vulnCounts[type].examples.push(text.substring(Math.max(0, idx - 20), idx + matches[0].length + 20));
            }
          }
        });
      });

      Object.entries(vulnCounts).forEach(([type, data]) => {
        result.vulnerabilities.push({
          type, severity: data.severity,
          detail: data.count + ' occurrence(s) of ' + type.replace(/_/g, ' ') + ' detected',
          examples: data.examples
        });
      });

      try {
        document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="checkbox"]):not([type="radio"])').forEach(input => {
          const name = (input.name || '').toLowerCase();
          const id = (input.id || '').toLowerCase();
          const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();
          const isSensitive = name.includes('ssn') || name.includes('social') || name.includes('credit') || name.includes('card') || name.includes('cvv') || name.includes('bank') || name.includes('passport') || id.includes('ssn') || id.includes('credit') || autocomplete.includes('cc-');
          if (isSensitive) {
            result.vulnerabilities.push({
              type: 'sensitive_input_field', severity: 'high',
              detail: 'Sensitive input field detected: name="' + (input.name || '') + '" id="' + (input.id || '') + '"'
            });
          }
        });
      } catch (e) {}

    } catch (error) {}
    return result;
  }
}

document.addEventListener('DOMContentLoaded', () => { new PrivacyScanner(); });
