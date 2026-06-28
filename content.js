class ComprehensiveWebsiteAnalyzer {
  constructor() {
    this.trackingPixels = [];
    this.networkRequests = [];
    this.fingerprintingAttempts = [];
    this.socialMediaWidgets = [];
    this.securityVulnerabilities = [];
    this.trackerCategories = { analytics: [], advertising: [], social: [], essential: [], cdn: [], unknown: [] };
    this.networkTimeline = [];
    this.storageAnalysis = null;
    this.webglInfo = null;
    this.cryptominers = [];
    this.detectedAdNetworks = [];
    this.performanceMetrics = {};
    this.cookieDetails = [];
    this.formDetails = [];
    this.linkAnalysis = { external: 0, internal: 0, suspicious: 0, phishing: 0, malware: 0, shorteners: 0 };
    this.metaTags = [];
    this._isSelfCreated = false;
    this.deepScanResults = {};

    this._storeRef();
    this.init();
  }

  _storeRef() {
    try {
      Object.defineProperty(window, '__privacyScanner', {
        value: this,
        writable: false,
        configurable: false
      });
    } catch (e) {
      window.__privacyScanner = this;
    }
  }

  init() {
    try {
      this.setupPerformanceMonitoring();
      this.setupNetworkTimeline();
      this.detectTrackingPixels();
      this.detectSocialWidgets();
      this.monitorFingerprintingAttempts();
      this.analyzeLocalStorage();
      this.detectAdNetworks();
      this.analyzeWebGL();
      this.detectCryptominers();
      this.analyzeSecurityVulnerabilities();
      this.categorizeTrackers();
      this.analyzeCookies();
      this.analyzeForms();
      this.analyzeLinks();
      this.analyzeMetaTags();
      this.runDeepScan();
    } catch (error) {
      console.error('[PrivacyScanner] Init error:', error);
    }
  }

  runDeepScan() {
    this.deepScanResults = {};
    const checks = [
      ['csp', () => this.deepAnalyzeCSP()],
      ['mixedContent', () => this.deepDetectMixedContent()],
      ['sri', () => this.deepAnalyzeSRI()],
      ['cors', () => this.deepAnalyzeCORS()],
      ['xss', () => this.deepDetectXSSPatterns()],
      ['clickjacking', () => this.deepAnalyzeClickjacking()],
      ['cookieSecurity', () => this.deepAnalyzeCookieSecurity()],
      ['localStorage', () => this.deepAnalyzeLocalStorage()],
      ['sessionStorage', () => this.deepAnalyzeSessionStorage()],
      ['indexedDB', () => this.deepAnalyzeIndexedDB()],
      ['permissions', () => this.deepDetectPermissions()],
      ['webrtc', () => this.deepAnalyzeWebRTC()],
      ['serviceWorker', () => this.deepAnalyzeServiceWorker()],
      ['cacheControl', () => this.deepAnalyzeCacheControl()],
      ['domVulnerabilities', () => this.deepAnalyzeDOMVulnerabilities()],
      ['resourceLoading', () => this.deepAnalyzeResourceLoading()],
      ['errorHandling', () => this.deepAnalyzeErrorHandling()],
      ['browserAPIs', () => this.deepDetectBrowserAPIAbuse()],
      ['cryptocurrency', () => this.deepDetectCryptocurrencyMining()],
      ['clipboard', () => this.deepDetectClipboardMonitoring()],
      ['geolocation', () => this.deepDetectGeolocationTracking()],
      ['mediaAccess', () => this.deepDetectMediaAccess()],
      ['notifications', () => this.deepDetectNotificationAbuse()],
      ['paymentAPIs', () => this.deepDetectPaymentAPIs()],
      ['credentialAPIs', () => this.deepDetectCredentialAPIs()],
      ['bluetoothUSB', () => this.deepDetectBluetoothUSB()],
      ['shadowDOM', () => this.deepDetectShadowDOM()],
      ['webWorkers', () => this.deepDetectWebWorkers()],
      ['webAssembly', () => this.deepDetectWebAssembly()],
      ['dnsPrefetch', () => this.deepDetectDNSPrefetch()],
      ['preconnect', () => this.deepDetectPreconnect()],
      ['linkPrefetch', () => this.deepDetectLinkPrefetch()],
      ['httpRedirects', () => this.deepAnalyzeHTTPRedirects()],
      ['contentTypes', () => this.deepAnalyzeContentTypes()],
      ['inputValidation', () => this.deepAnalyzeInputValidation()],
      ['autocomplete', () => this.deepAnalyzeAutocomplete()],
      ['externalFonts', () => this.deepDetectExternalFonts()],
      ['externalStyles', () => this.deepDetectExternalStyles()],
      ['iframeSandbox', () => this.deepAnalyzeIframeSandbox()],
      ['objectEmbed', () => this.deepDetectObjectEmbed()],
      ['applets', () => this.deepDetectApplets()],
      ['dataExfil', () => this.deepDetectDataExfiltration()],
      ['keylogging', () => this.deepDetectKeylogging()],
      ['formjacking', () => this.deepDetectFormjacking()],
      ['magecart', () => this.deepDetectMagecart()],
      ['sessionFixation', () => this.deepDetectSessionFixation()],
      ['csrf', () => this.deepDetectCSRF()],
      ['openRedirect', () => this.deepDetectOpenRedirects()],
      ['pathTraversal', () => this.deepDetectPathTraversal()],
      ['sqlInjection', () => this.deepDetectSQLInjectionPatterns()],
      ['xxe', () => this.deepDetectXXE()],
      ['ssrf', () => this.deepDetectSSRF()],
      ['dnsRebinding', () => this.deepDetectDNSRebinding()],
      ['subresourceIntegrity', () => this.deepDetectSRI()],
      ['mixedProtocol', () => this.deepDetectMixedProtocol()],
      ['insecureForm', () => this.deepDetectInsecureFormActions()],
      ['autofill', () => this.deepDetectAutofillAbuse()],
      ['fingerprint2', () => this.deepDetectFingerprintJS()],
      ['canvas2', () => this.deepDetectCanvasFingerprinting()],
      ['webgl2', () => this.deepDetectWebGLFingerprinting()],
      ['audio2', () => this.deepDetectAudioFingerprinting()],
      ['font2', () => this.deepDetectFontFingerprinting()],
      ['screen2', () => this.deepDetectScreenFingerprinting()],
      ['navigator2', () => this.deepDetectNavigatorFingerprinting()],
      ['battery', () => this.deepDetectBatteryAPI()],
      ['connection', () => this.deepDetectConnectionAPI()],
      ['speech', () => this.deepDetectSpeechRecognition()],
      ['vr', () => this.deepDetectVRAR()],
      ['nfc', () => this.deepDetectNFC()],
      ['gamepad', () => this.deepDetectGamepadAPI()],
      ['serial', () => this.deepDetectSerialAPI()],
      ['usb', () => this.deepDetectUSBDeviceAPI()],
      ['hid', () => this.deepDetectHID()],
      ['wakeLock', () => this.deepDetectWakeLock()],
      ['presentation', () => this.deepDetectPresentationAPI()],
      ['backgroundSync', () => this.deepDetectBackgroundSync()],
      ['pushAPI', () => this.deepDetectPushAPI()],
      ['periodicSync', () => this.deepDetectPeriodicSync()],
      ['contentIndexing', () => this.deepDetectContentIndexing()],
      ['shareAPI', () => this.deepDetectShareAPI()],
      ['contacts', () => this.deepDetectContactsAPI()],
      ['credentials', () => this.deepDetectCredentialsAPI()],
      ['webShare', () => this.deepDetectWebShare()],
      ['fileSystem', () => this.deepDetectFileSystemAPI()],
      ['storageAPI', () => this.deepDetectStorageAPI()],
      ['permissionAPI', () => this.deepDetectPermissionStatus()],
      ['clipboardRead', () => this.deepDetectClipboardRead()],
      ['clipboardWrite', () => this.deepDetectClipboardWrite()],
      ['mediaRecorder', () => this.deepDetectMediaRecorder()],
      ['imageCapture', () => this.deepDetectImageCapture()],
      ['barcode', () => this.deepDetectBarcodeDetector()],
      ['faceDetection', () => this.deepDetectFaceDetection()],
      ['textDetection', () => this.deepDetectTextDetection()],
      ['styleDetection', () => this.deepDetectStyleDetection()],
      ['cookieSync', () => this.deepDetectCookieSync()],
      ['evercookies', () => this.deepDetectEvercookies()],
      ['cacheTiming', () => this.deepDetectCacheTiming()],
      ['historySniffing', () => this.deepDetectHistorySniffing()],
      ['plugins', () => this.deepDetectPluginEnumeration()],
      ['mimeTypes', () => this.deepDetectMimeTypeEnumeration()],
      ['mediaDevices', () => this.deepDetectMediaDevices()],
      ['speechSynthesis', () => this.deepDetectSpeechSynthesis()],
      ['speechRecog', () => this.deepDetectSpeechRecognitionAPI()],
      ['midi', () => this.deepDetectMIDI()],
      ['sensor', () => this.deepDetectSensorAPIs()],
      ['observers', () => this.deepDetectMutationObservers()],
      ['timers', () => this.deepDetectTimerAbuse()],
      ['workerSpam', () => this.deepDetectWorkerSpam()],
      ['cryptoMining', () => this.deepDetectCryptoMiningExpanded()],
      ['adInjection', () => this.deepDetectAdInjection()],
      ['affiliate', () => this.deepDetectAffiliateTracking()],
      ['fingerprinting3', () => this.deepDetectAdvancedFingerprinting()]
    ];
    const CHUNK_SIZE = 15;
    const processChunk = (startIdx) => {
      if (startIdx >= checks.length) return;
      const endIdx = Math.min(startIdx + CHUNK_SIZE, checks.length);
      for (let i = startIdx; i < endIdx; i++) {
        try { this.deepScanResults[checks[i][0]] = checks[i][1](); } catch (e) {}
      }
      if (endIdx < checks.length) {
        if (typeof requestIdleCallback !== 'undefined') {
          requestIdleCallback(() => processChunk(endIdx), { timeout: 50 });
        } else {
          setTimeout(() => processChunk(endIdx), 0);
        }
      }
    };
    processChunk(0);
  }

  setupPerformanceMonitoring() {
    try {
      if (window.performance && window.performance.timing) {
        const timing = window.performance.timing;
        this.performanceMetrics = {
          domLoading: timing.domLoading - timing.navigationStart,
          domInteractive: timing.domInteractive - timing.navigationStart,
          domComplete: timing.domComplete - timing.navigationStart,
          loadEventEnd: timing.loadEventEnd - timing.navigationStart
        };
      }
      if (window.performance && window.performance.getEntriesByType) {
        const resources = window.performance.getEntriesByType('resource');
        this.performanceMetrics.totalResources = resources.length;
        this.performanceMetrics.slowResources = resources.filter(r => r.duration > 1000).length;
        this.performanceMetrics.largeResources = resources.filter(r => r.transferSize > 500000).length;
        this.performanceMetrics.resourceTypes = {};
        resources.forEach(r => {
          const type = r.initiatorType || 'other';
          this.performanceMetrics.resourceTypes[type] = (this.performanceMetrics.resourceTypes[type] || 0) + 1;
        });
      }
    } catch (error) {}
  }

  setupNetworkTimeline() {
    try {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          this.networkTimeline.push({
            name: entry.name,
            type: entry.initiatorType,
            startTime: Math.round(entry.startTime),
            duration: Math.round(entry.duration),
            transferSize: entry.transferSize || 0
          });
        }
      });
      observer.observe({ type: 'resource', buffered: true });
      this._networkObserver = observer;
    } catch (error) {}
  }

  detectTrackingPixels() {
    try {
      const images = document.querySelectorAll('img');
      images.forEach(img => {
        if (this.isTrackingPixel(img)) {
          this.trackingPixels.push({
            src: this._sanitizeUrl(img.src),
            type: 'image_pixel',
            hidden: img.style.display === 'none' || img.style.visibility === 'hidden',
            dimensions: `${img.width}x${img.height}`
          });
        }
      });
      this.detectIframeTracking();
    } catch (error) {}
  }

  isTrackingPixel(img) {
    if (img.width <= 1 && img.height <= 1) return true;
    if (img.style.width === '1px' && img.style.height === '1px') return true;
    if (img.style.display === 'none' && img.src && img.src.length > 50) return true;
    if (img.style.visibility === 'hidden' && img.src) return true;
    if (img.getAttribute('width') === '1' && img.getAttribute('height') === '1') return true;
    if (img.style.position === 'absolute' && img.style.opacity === '0') return true;
    if (img.naturalWidth <= 1 && img.naturalHeight <= 1 && img.src.length > 50) return true;
    return false;
  }

  detectIframeTracking() {
    try {
      const iframes = document.querySelectorAll('iframe');
      iframes.forEach(iframe => {
        const w = parseInt(iframe.width) || iframe.offsetWidth;
        const h = parseInt(iframe.height) || iframe.offsetHeight;
        if ((w <= 1 && h <= 1) && iframe.src) {
          this.trackingPixels.push({
            src: this._sanitizeUrl(iframe.src),
            type: 'iframe_pixel',
            dimensions: `${w}x${h}`
          });
        }
        if (iframe.style.display === 'none' || iframe.style.visibility === 'hidden') {
          if (iframe.src && iframe.src.length > 30) {
            this.trackingPixels.push({
              src: this._sanitizeUrl(iframe.src),
              type: 'hidden_iframe',
              dimensions: `${w}x${h}`
            });
          }
        }
      });
    } catch (error) {}
  }

  detectSocialWidgets() {
    try {
      const domains = self.__privacyDomains || {};
      const socialDomains = domains.socialDomains || [];
      const socialWidgetSelectors = domains.socialWidgetSelectors || [];

      const platformMap = {};
      socialDomains.forEach(d => {
        if (d.includes('facebook') || d.includes('fb.') || d.includes('fbcdn')) platformMap[d] = 'facebook';
        else if (d.includes('twitter') || d === 't.co' || d.includes('twimg')) platformMap[d] = 'twitter';
        else if (d.includes('instagram') || d.includes('cdninstagram')) platformMap[d] = 'instagram';
        else if (d.includes('linkedin') || d.includes('licdn')) platformMap[d] = 'linkedin';
        else if (d.includes('youtube') || d.includes('youtu.be') || d.includes('ytimg')) platformMap[d] = 'youtube';
        else if (d.includes('tiktok')) platformMap[d] = 'tiktok';
        else if (d.includes('pinterest') || d.includes('pinimg')) platformMap[d] = 'pinterest';
      });

      const iframes = document.querySelectorAll('iframe[src]');
      iframes.forEach(iframe => {
        const src = iframe.src.toLowerCase();
        socialDomains.forEach(domain => {
          if (src.includes(domain)) {
            this.socialMediaWidgets.push({
              platform: platformMap[domain] || 'unknown', type: 'iframe', src: this._sanitizeUrl(iframe.src)
            });
          }
        });
      });

      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        const src = script.src.toLowerCase();
        socialDomains.forEach(domain => {
          if (src.includes(domain)) {
            this.socialMediaWidgets.push({
              platform: platformMap[domain] || 'unknown', type: 'script', src: this._sanitizeUrl(script.src)
            });
          }
        });
      });

      socialWidgetSelectors.forEach(selector => {
        try {
          const elements = document.querySelectorAll(selector);
          elements.forEach(el => {
            this.socialMediaWidgets.push({
              platform: this._detectPlatformFromElement(el),
              type: 'widget', element: el.tagName.toLowerCase()
            });
          });
        } catch (e) {}
      });
    } catch (error) {}
  }

  _detectPlatformFromElement(el) {
    const cls = (el.className || '').toLowerCase();
    if (cls.includes('fb') || cls.includes('facebook')) return 'facebook';
    if (cls.includes('twitter') || cls.includes('tweet')) return 'twitter';
    if (cls.includes('linkedin')) return 'linkedin';
    if (cls.includes('pinterest') || cls.includes('pin')) return 'pinterest';
    return 'unknown';
  }

  monitorFingerprintingAttempts() {
    this._setupMainWorldFingerprintListener();
    this._monitorFontDetection();
  }

  _setupMainWorldFingerprintListener() {
    document.addEventListener('__privacyScannerFingerprint', (e) => {
      if (e.detail) {
        this.fingerprintingAttempts.push(e.detail);
      }
    });
  }

  _monitorFontDetection() {
    try {
      const observer = new MutationObserver(mutations => {
        mutations.forEach(mutation => {
          if (mutation.type === 'childList') {
            mutation.addedNodes.forEach(node => {
              if (node.nodeType === 1 && node.tagName === 'STYLE') {
                const content = node.textContent || '';
                if (content.includes('font-family') || content.includes('@font-face')) {
                  this.fingerprintingAttempts.push({
                    type: 'font_detection_style',
                    timestamp: Date.now()
                  });
                }
              }
            });
          }
        });
      });
      observer.observe(document.head || document.documentElement, {
        childList: true, subtree: true
      });
    } catch (error) {}
  }

  analyzeLocalStorage() {
    try {
      this.storageAnalysis = {
        localStorage: { items: 0, trackingKeys: [], totalSize: 0 },
        sessionStorage: { items: 0, trackingKeys: [], totalSize: 0 }
      };
      try {
        const data = { ...localStorage };
        this.storageAnalysis.localStorage.items = Object.keys(data).length;
        this.storageAnalysis.localStorage.trackingKeys = this._findTrackingKeys(data);
        this.storageAnalysis.localStorage.totalSize = JSON.stringify(data).length;
      } catch (e) {}
      try {
        const data = { ...sessionStorage };
        this.storageAnalysis.sessionStorage.items = Object.keys(data).length;
        this.storageAnalysis.sessionStorage.trackingKeys = this._findTrackingKeys(data);
        this.storageAnalysis.sessionStorage.totalSize = JSON.stringify(data).length;
      } catch (e) {}
    } catch (error) {}
  }

  _findTrackingKeys(storageData) {
    const patterns = self.__privacyDomains?.trackingCookiePatterns || [];
    return Object.keys(storageData).filter(key =>
      patterns.some(p => key.toLowerCase().includes(p.toLowerCase()))
    );
  }

  detectAdNetworks() {
    try {
      const adNetworks = self.__privacyDomains?.adNetworks || [];
      this.detectedAdNetworks = [];
      const scripts = document.querySelectorAll('script[src]');
      scripts.forEach(script => {
        adNetworks.forEach(network => {
          if (script.src.includes(network) && !this.detectedAdNetworks.includes(network)) {
            this.detectedAdNetworks.push(network);
          }
        });
      });
      const links = document.querySelectorAll('link[href]');
      links.forEach(link => {
        adNetworks.forEach(network => {
          if (link.href.includes(network) && !this.detectedAdNetworks.includes(network)) {
            this.detectedAdNetworks.push(network);
          }
        });
      });
      const allElements = document.querySelectorAll('[src], [href]');
      allElements.forEach(el => {
        const url = el.src || el.href || '';
        adNetworks.forEach(network => {
          if (url.includes(network) && !this.detectedAdNetworks.includes(network)) {
            this.detectedAdNetworks.push(network);
          }
        });
      });
    } catch (error) {}
  }

  analyzeWebGL() {
    try {
      this._isSelfCreated = true;
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      this._isSelfCreated = false;
      this.webglInfo = null;
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        this.webglInfo = {
          vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
          renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
          version: gl.getParameter(gl.VERSION),
          extensions: gl.getSupportedExtensions()?.length || 0
        };
      }
    } catch (error) {
      this._isSelfCreated = false;
      this.webglInfo = null;
    }
  }

  detectCryptominers() {
    try {
      const minerPatterns = self.__privacyDomains?.cryptominingPatterns || [];
      this.cryptominers = [];
      document.querySelectorAll('script').forEach(script => {
        const content = (script.textContent || script.src || '').toLowerCase();
        minerPatterns.forEach(pattern => {
          if (content.includes(pattern)) {
            this.cryptominers.push({
              type: 'potential_cryptominer',
              pattern,
              source: script.src ? this._sanitizeUrl(script.src) : 'inline'
            });
          }
        });
      });
    } catch (error) {}
  }

  analyzeSecurityVulnerabilities() {
    try {
      this.securityVulnerabilities = [];
      document.querySelectorAll('form').forEach(form => {
        const action = form.action || '';
        if (action && !action.startsWith('https://') && !action.startsWith('/') && action !== window.location.href) {
          this.securityVulnerabilities.push({
            type: 'insecure_form_action',
            severity: 'high',
            detail: 'Form submits to non-HTTPS URL'
          });
        }
      });
      let inlineScriptCount = 0;
      document.querySelectorAll('script:not([src])').forEach(script => {
        const content = script.textContent || '';
        if (content.includes('eval(') || content.includes('innerHTML')) {
          inlineScriptCount++;
        }
      });
      if (inlineScriptCount > 0) {
        this.securityVulnerabilities.push({
          type: 'unsafe_script_pattern',
          severity: 'medium',
          detail: `${inlineScriptCount} inline script(s) use eval() or innerHTML`
        });
      }
    } catch (error) {}
  }

  analyzeCookies() {
    try {
      this.cookieDetails = [];
      const cookies = document.cookie.split(';').filter(c => c.trim());
      cookies.forEach(cookie => {
        const [nameValue] = cookie.split('=');
        const name = nameValue.trim();
        this.cookieDetails.push({
          name,
          hasTrackingPattern: this._isTrackingCookie(name)
        });
      });
    } catch (error) {}
  }

  _isTrackingCookie(name) {
    const d = window.__privacyDomains || {};
    const patterns = d.trackingCookiePatterns || ['_ga', '_gid', '_gat', '_fbp', '_fbc', '_hjid', '__utma', 'utm_', '_clck', '_pk_'];
    return patterns.some(p => name.toLowerCase().includes(p));
  }

  analyzeForms() {
    try {
      this.formDetails = [];
      document.querySelectorAll('form').forEach(form => {
        const inputs = form.querySelectorAll('input, textarea, select');
        const fields = [];
        inputs.forEach(input => {
          fields.push({
            type: input.type || 'text',
            name: input.name || '',
            hasAutocomplete: input.hasAttribute('autocomplete'),
            autocompleteValue: input.getAttribute('autocomplete') || ''
          });
        });
        this.formDetails.push({
          action: form.action || window.location.href,
          method: (form.method || 'get').toLowerCase(),
          fieldCount: fields.length,
          hasPassword: fields.some(f => f.type === 'password'),
          hasEmail: fields.some(f => f.type === 'email'),
          fields: fields.slice(0, 10)
        });
      });
    } catch (error) {}
  }

  analyzeLinks() {
    try {
      const links = document.querySelectorAll('a[href]');
      const currentHost = window.location.hostname;
      const phishingPatterns = ['login', 'signin', 'verify', 'account', 'secure', 'banking', 'paypal', 'ebay', 'amazon'];
      const malwarePatterns = ['download', 'exe', 'bat', 'cmd', 'ps1', 'vbs', 'js:', 'data:', 'blob:'];
      const shortenerDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'rb.gy', 'cutt.ly'];

      links.forEach(link => {
        try {
          const url = new URL(link.href, window.location.href);
          if (url.hostname === currentHost) {
            this.linkAnalysis.internal++;
          } else {
            this.linkAnalysis.external++;
            if (shortenerDomains.some(s => url.hostname.includes(s))) {
              this.linkAnalysis.shorteners++;
              this.linkAnalysis.suspicious++;
            }
            if (phishingPatterns.some(p => url.pathname.toLowerCase().includes(p)) && url.hostname !== currentHost) {
              this.linkAnalysis.phishing++;
            }
            if (malwarePatterns.some(p => url.pathname.toLowerCase().endsWith(p))) {
              this.linkAnalysis.malware++;
            }
            if (this._isSuspiciousLink(url.hostname)) {
              this.linkAnalysis.suspicious++;
            }
          }
        } catch (e) {}
      });
    } catch (error) {}
  }

  _isSuspiciousLink(hostname) {
    const suspicious = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd'];
    return suspicious.some(s => hostname.includes(s));
  }

  analyzeMetaTags() {
    try {
      this.metaTags = [];
      document.querySelectorAll('meta').forEach(meta => {
        const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
        const content = meta.getAttribute('content') || '';
        if (name && content) {
          this.metaTags.push({ name: name.toLowerCase(), content: content.substring(0, 200) });
        }
      });
    } catch (error) {}
  }

  categorizeTrackers() {
    const categories = { analytics: [], advertising: [], social: [], essential: [], cdn: [], unknown: [] };
    const domains = self.__privacyDomains || {};
    const analyticsDomains = domains.analyticsDomains || [];
    const adDomains = domains.adNetworks || [];
    const socialDomains = domains.socialDomains || [];
    const essentialDomains = domains.essentialDomains || [];
    const cdnDomains = domains.cdnDomains || [];

    const allTrackers = new Set();
    if (this.detectedAdNetworks) this.detectedAdNetworks.forEach(d => allTrackers.add(d));
    this.socialMediaWidgets.forEach(w => {
      if (w.src) {
        try { allTrackers.add(new URL(w.src).hostname); } catch(e) {}
      }
    });
    this.trackingPixels.forEach(p => {
      if (p.src) {
        try { allTrackers.add(new URL(p.src, location.href).hostname); } catch(e) {}
      }
    });

    allTrackers.forEach(domain => {
      if (analyticsDomains.some(d => domain.includes(d))) categories.analytics.push(domain);
      else if (adDomains.some(d => domain.includes(d))) categories.advertising.push(domain);
      else if (socialDomains.some(d => domain.includes(d))) categories.social.push(domain);
      else if (cdnDomains.some(d => domain.includes(d))) categories.cdn.push(domain);
      else if (essentialDomains.some(d => domain.includes(d))) categories.essential.push(domain);
      else categories.unknown.push(domain);
    });
    this.trackerCategories = categories;
  }

  _sanitizeUrl(url) {
    try {
      const u = new URL(url, location.href);
      return u.origin + u.pathname;
    } catch (e) {
      return '';
    }
  }

  getScanResults() {
    return {
      trackingPixels: this.trackingPixels,
      socialMediaWidgets: this.socialMediaWidgets,
      fingerprintingAttempts: this.fingerprintingAttempts,
      cryptominers: this.cryptominers,
      adNetworks: this.detectedAdNetworks,
      webgl: this.webglInfo,
      storage: this.storageAnalysis,
      vulnerabilities: this.securityVulnerabilities,
      performanceMetrics: this.performanceMetrics,
      trackerCategories: this.trackerCategories,
      networkTimeline: this.networkTimeline.slice(0, 200),
      cookieDetails: this.cookieDetails,
      formDetails: this.formDetails,
      linkAnalysis: this.linkAnalysis,
      metaTags: this.metaTags,
      deepScanResults: this.deepScanResults
    };
  }

  _getDocHTML() {
    try {
      return document.documentElement.outerHTML || '';
    } catch (e) {
      return '';
    }
  }

  _getAllScriptSources() {
    try {
      const sources = [];
      document.querySelectorAll('script[src]').forEach(s => sources.push(s.src));
      document.querySelectorAll('script:not([src])').forEach(s => sources.push('inline:' + (s.textContent || '').substring(0, 500)));
      return sources;
    } catch (e) {
      return [];
    }
  }

  _getAllIframes() {
    try {
      return Array.from(document.querySelectorAll('iframe')).map(f => ({
        src: f.src, sandbox: f.sandbox?.value || '', width: f.width, height: f.height,
        style: f.style.cssText || '', loading: f.loading || ''
      }));
    } catch (e) {
      return [];
    }
  }

  deepAnalyzeCSP() {
    const result = { hasCSP: false, directives: {}, issues: [], score: 0 };
    try {
      const metaCSP = document.querySelector('meta[http-equiv="content-security-policy"]');
      if (metaCSP) {
        result.hasCSP = true;
        const policy = metaCSP.getAttribute('content') || '';
        result.policy = policy.substring(0, 500);
        result.directives = this._parseCSP(policy);
      }
      const scripts = this._getAllScriptSources();
      const inlineCount = scripts.filter(s => s.startsWith('inline:')).length;
      const externalCount = scripts.filter(s => !s.startsWith('inline:')).length;
      result.inlineScripts = inlineCount;
      result.externalScripts = externalCount;
      if (inlineCount > 0 && !result.hasCSP) {
        result.issues.push({ type: 'no_csp_with_inline_scripts', severity: 'high' });
      }
      if (result.hasCSP) {
        const policy = result.policy || '';
        if (policy.includes("'unsafe-inline'")) result.issues.push({ type: 'unsafe_inline', severity: 'medium' });
        if (policy.includes("'unsafe-eval'")) result.issues.push({ type: 'unsafe_eval', severity: 'high' });
        if (policy.includes('data:')) result.issues.push({ type: 'data_uri_allowed', severity: 'low' });
        if (!policy.includes("'strict-dynamic'") && !policy.includes("'nonce-'")) {
          result.issues.push({ type: 'weak_csp_no_nonce', severity: 'medium' });
        }
      }
      if (!result.hasCSP && (inlineCount > 5 || externalCount > 20)) {
        result.issues.push({ type: 'no_csp_high_script_count', severity: 'high' });
      }
      result.score = result.hasCSP ? (10 - result.issues.length) : 0;
    } catch (e) {}
    return result;
  }

  _parseCSP(policy) {
    const directives = {};
    try {
      policy.split(';').forEach(d => {
        const parts = d.trim().split(/\s+/);
        if (parts.length > 0) directives[parts[0]] = parts.slice(1);
      });
    } catch (e) {}
    return directives;
  }

  deepDetectMixedContent() {
    const result = { issues: [], count: 0 };
    try {
      if (window.location.protocol !== 'https:') return result;
      document.querySelectorAll('img[src], script[src], link[href], iframe[src], video[src], audio[src], source[src], embed[src], object[data]').forEach(el => {
        const url = el.src || el.href || el.data || '';
        if (url.startsWith('http://')) {
          result.issues.push({ type: el.tagName.toLowerCase(), url: url.substring(0, 200) });
          result.count++;
        }
      });
      document.querySelectorAll('[style*="url("]').forEach(el => {
        const style = el.getAttribute('style') || '';
        const match = style.match(/url\(["']?http:\/\/[^"')]+/);
        if (match) {
          result.issues.push({ type: 'style_url', url: match[0].substring(0, 200) });
          result.count++;
        }
      });
    } catch (e) {}
    return result;
  }

  deepAnalyzeSRI() {
    const result = { total: 0, withIntegrity: 0, withoutIntegrity: 0, issues: [] };
    try {
      document.querySelectorAll('script[src], link[rel="stylesheet"][href]').forEach(el => {
        result.total++;
        if (el.integrity) {
          result.withIntegrity++;
        } else {
          result.withoutIntegrity++;
          if (el.tagName === 'SCRIPT') {
            result.issues.push({ type: 'missing_sri_script', src: el.src?.substring(0, 200) || '' });
          }
        }
      });
      result.ratio = result.total > 0 ? result.withIntegrity / result.total : 1;
    } catch (e) {}
    return result;
  }

  deepAnalyzeCORS() {
    const result = { crossOriginElements: 0, issues: [] };
    try {
      document.querySelectorAll('[crossorigin]').forEach(el => {
        result.crossOriginElements++;
        const val = el.getAttribute('crossorigin');
        if (val === '' || val === 'anonymous') {
          result.issues.push({ type: 'crossorigin_anonymous', tag: el.tagName.toLowerCase() });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectXSSPatterns() {
    const result = { issues: [], patterns: [] };
    try {
      const xssRegexes = [
        { re: /document\.write\s*\(/g, name: 'document.write' },
        { re: /\.innerHTML\s*=/g, name: 'innerHTML' },
        { re: /\.outerHTML\s*=/g, name: 'outerHTML' },
        { re: /\beval\s*\(/g, name: 'eval' },
        { re: /\bFunction\s*\(/g, name: 'Function constructor' },
        { re: /setTimeout\s*\(\s*['"]/g, name: 'string_timeout' },
        { re: /setInterval\s*\(\s*['"]/g, name: 'string_interval' },
        { re: /\.insertAdjacentHTML/g, name: 'insertAdjacentHTML' },
        { re: /document\.location\s*=/g, name: 'location_assign' },
        { re: /window\.location\s*=/g, name: 'window_location_assign' },
        { re: /document\.domain/g, name: 'document.domain' },
        { re: /postMessage.*origin/g, name: 'postMessage' }
      ];
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.length > 50000) return;
        const seen = new Set();
        xssRegexes.forEach(({ re, name }) => {
          re.lastIndex = 0;
          if (re.test(content) && !seen.has(name)) {
            result.patterns.push(name);
            seen.add(name);
          }
        });
      });
      document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]').forEach(el => {
        result.patterns.push('inline_event_handler:' + el.tagName.toLowerCase());
      });
      if (result.patterns.length > 0) {
        result.issues.push({ type: 'xss_risk_patterns', severity: 'medium', patterns: result.patterns.slice(0, 20) });
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeClickjacking() {
    const result = { issues: [], xFrameOptions: false, CSP_frame: false };
    try {
      const iframes = document.querySelectorAll('iframe');
      iframes.forEach(iframe => {
        const w = parseInt(iframe.width) || iframe.offsetWidth;
        const h = parseInt(iframe.height) || iframe.offsetHeight;
        if (w > 300 && h > 250 && iframe.style.position !== 'absolute' && !iframe.sandbox?.value) {
          result.issues.push({ type: 'large_unsandboxed_iframe', dimensions: `${w}x${h}` });
        }
      });
    } catch (e) {}
    return result;
  }

  deepAnalyzeCookieSecurity() {
    const result = { cookies: [], issues: [], totalCookies: 0, trackingCookies: 0 };
    try {
      const cookies = document.cookie.split(';').filter(c => c.trim());
      result.totalCookies = cookies.length;
      const trackingPatterns = (window.__privacyDomains && window.__privacyDomains.trackingCookiePatterns) || ['_ga', '_gid', '_gat', '_fbp', '_fbc', '_hjid', '__utma', 'utm_', '_clck', '_pk_', '_fbp_', 'fr', 'IDE', 'NID', '1p_jar', 'CONSENT', 'GPS', 'VISITOR_INFO1', 'YSC', 'S', 'SID', 'HSID', 'SSID', 'APISID', 'SAPISID'];
      cookies.forEach(cookie => {
        const [nameValue] = cookie.split('=');
        const name = nameValue.trim();
        const isTracking = trackingPatterns.some(p => name.toLowerCase().includes(p.toLowerCase()));
        if (isTracking) result.trackingCookies++;
        result.cookies.push({ name, isTracking });
        if (!isTracking) {
          return;
        }
        result.issues.push({ type: 'tracking_cookie', cookie: name });
      });
    } catch (e) {}
    return result;
  }

  deepAnalyzeLocalStorage() {
    const result = { items: 0, totalSize: 0, trackingKeys: [], largeValues: [], issues: [] };
    try {
      const keys = Object.keys(localStorage);
      result.items = keys.length;
      let totalSize = 0;
      keys.forEach(key => {
        const value = localStorage.getItem(key) || '';
        totalSize += key.length + value.length;
        if (value.length > 10000) result.largeValues.push({ key, size: value.length });
        if (this._isTrackingKey(key)) result.trackingKeys.push(key);
        if (value.includes('http://')) result.issues.push({ type: 'insecure_url_in_storage', key });
      });
      result.totalSize = totalSize;
      if (result.trackingKeys.length > 0) {
        result.issues.push({ type: 'tracking_data_in_storage', keys: result.trackingKeys.slice(0, 10) });
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeSessionStorage() {
    const result = { items: 0, totalSize: 0, issues: [] };
    try {
      const keys = Object.keys(sessionStorage);
      result.items = keys.length;
      let totalSize = 0;
      keys.forEach(key => {
        const value = sessionStorage.getItem(key) || '';
        totalSize += key.length + value.length;
      });
      result.totalSize = totalSize;
    } catch (e) {}
    return result;
  }

  deepAnalyzeIndexedDB() {
    const result = { databases: [], issues: [] };
    try {
      if (window.indexedDB && window.indexedDB.databases) {
        window.indexedDB.databases().then(dbs => {
          result.databases = dbs.map(db => ({ name: db.name, version: db.version }));
        }).catch(() => {});
      }
    } catch (e) {}
    return result;
  }

  deepDetectPermissions() {
    const result = { permissions: [], issues: [] };
    try {
      if (navigator.permissions) {
        const permList = ['camera', 'microphone', 'geolocation', 'notifications', 'midi', 'push', 'clipboard-read', 'clipboard-write'];
        permList.forEach(perm => {
          navigator.permissions.query({ name: perm }).then(status => {
            result.permissions.push({ name: perm, state: status.state });
            if (status.state === 'granted') {
              result.issues.push({ type: 'permission_granted', permission: perm });
            }
          }).catch(() => {});
        });
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeWebRTC() {
    const result = { available: false, issues: [] };
    try {
      if (window.RTCPeerConnection || window.webkitRTCPeerConnection) {
        result.available = true;
        result.issues.push({ type: 'webrtc_available', severity: 'info' });
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeServiceWorker() {
    const result = { registered: false, scope: '', issues: [] };
    try {
      if ('serviceWorker' in navigator) {
        navigator.serviceWorker.getRegistrations().then(regs => {
          result.registered = regs.length > 0;
          result.scope = regs.length > 0 ? regs[0].scope : '';
          if (regs.length > 0) {
            result.issues.push({ type: 'service_worker_active', scope: regs[0].scope });
          }
        }).catch(() => {});
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeCacheControl() {
    const result = { issues: [] };
    try {
      if (document.cookie) {
        result.issues.push({ type: 'cookies_accessible', severity: 'info' });
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeDOMVulnerabilities() {
    const result = { issues: [], patterns: [] };
    try {
      const domRegexes = [
        { re: /document\.write/g, name: 'document.write' },
        { re: /\.innerHTML.*user|user.*\.innerHTML/g, name: 'user_input_to_innerHTML' },
        { re: /location\.hash.*innerHTML|innerHTML.*location\.hash/g, name: 'hash_to_innerHTML' },
        { re: /location\.search.*innerHTML|innerHTML.*location\.search/g, name: 'search_to_innerHTML' },
        { re: /document\.referrer.*innerHTML|innerHTML.*document\.referrer/g, name: 'referrer_to_innerHTML' },
        { re: /window\.name.*innerHTML|innerHTML.*window\.name/g, name: 'window_name_to_innerHTML' }
      ];
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        const seen = new Set();
        domRegexes.forEach(({ re, name }) => {
          re.lastIndex = 0;
          if (re.test(content) && !seen.has(name)) {
            result.patterns.push(name);
            seen.add(name);
          }
        });
      });
      document.querySelectorAll('a[href^="javascript:"]').forEach(a => {
        result.patterns.push('javascript_protocol_link');
      });
      document.querySelectorAll('[formaction]').forEach(el => {
        const action = el.getAttribute('formaction') || '';
        if (action.startsWith('javascript:')) result.patterns.push('javascript_formaction');
      });
      if (result.patterns.length > 0) {
        result.issues.push({ type: 'dom_xss_risks', patterns: result.patterns.slice(0, 20) });
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeResourceLoading() {
    const result = { total: 0, byType: {}, issues: [] };
    try {
      if (window.performance && window.performance.getEntriesByType) {
        const resources = window.performance.getEntriesByType('resource');
        result.total = resources.length;
        resources.forEach(r => {
          const type = r.initiatorType || 'other';
          result.byType[type] = (result.byType[type] || 0) + 1;
        });
        const largeResources = resources.filter(r => r.transferSize > 1000000);
        if (largeResources.length > 0) {
          result.issues.push({ type: 'large_resources', count: largeResources.length });
        }
        const slowResources = resources.filter(r => r.duration > 3000);
        if (slowResources.length > 0) {
          result.issues.push({ type: 'slow_resources', count: slowResources.length });
        }
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeErrorHandling() {
    const result = { issues: [], hasErrorListeners: false };
    try {
      window.addEventListener('error', () => { result.hasErrorListeners = true; });
      window.addEventListener('unhandledrejection', () => { result.hasErrorListeners = true; });
    } catch (e) {}
    return result;
  }

  deepDetectBrowserAPIAbuse() {
    const result = { apis: [], issues: [] };
    try {
      if (navigator.geolocation) result.apis.push('geolocation');
      if (navigator.vibrate) result.apis.push('vibrate');
      if (navigator.sendBeacon) result.apis.push('sendBeacon');
      if (window.fetch) result.apis.push('fetch');
      if (window.XMLHttpRequest) result.apis.push('xhr');
      if (navigator.serviceWorker) result.apis.push('serviceWorker');
      if (window.caches) result.apis.push('cacheAPI');
      if (window.paymentRequest) result.apis.push('paymentRequest');
      if (navigator.credentials) result.apis.push('credentials');
      if (navigator.share) result.apis.push('webShare');
      if (navigator.mediaDevices) result.apis.push('mediaDevices');
      if (window.WebSocket) result.apis.push('websocket');
      if (window.EventSource) result.apis.push('eventSource');
      if (navigator.sendBeacon) {
        result.issues.push({ type: 'send_beacon_available', severity: 'info' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectCryptocurrencyMining() {
    const result = { miners: [], issues: [] };
    try {
      const d = window.__privacyDomains || {};
      const patterns = d.cryptominingPatterns || ['coinhive', 'cryptoloot', 'coin-imp', 'coinhave', 'coinerr', 'minero', 'webminepool', 'coinhive.com', 'authedmine.com', 'jsecoin', 'cryptonight'];
      const scripts = document.querySelectorAll('script');
      scripts.forEach(script => {
        const content = (script.textContent || '').toLowerCase();
        const src = (script.src || '').toLowerCase();
        patterns.forEach(pattern => {
          if (content.includes(pattern) || src.includes(pattern)) {
            result.miners.push({ pattern, source: script.src || 'inline' });
          }
        });
      });
      if (result.miners.length > 0) {
        result.issues.push({ type: 'cryptomining_detected', count: result.miners.length });
      }
    } catch (e) {}
    return result;
  }

  deepDetectClipboardMonitoring() {
    const result = { issues: [], hasClipboardListeners: false };
    try {
      document.addEventListener('copy', () => { result.hasClipboardListeners = true; });
      document.addEventListener('paste', () => { result.hasClipboardListeners = true; });
      document.addEventListener('cut', () => { result.hasClipboardListeners = true; });
    } catch (e) {}
    return result;
  }

  deepDetectGeolocationTracking() {
    const result = { issues: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('navigator.geolocation')) {
          result.issues.push({ type: 'geolocation_api_used' });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectMediaAccess() {
    const result = { issues: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('getUserMedia') || content.includes('getDisplayMedia')) {
          result.issues.push({ type: 'media_access_api_used' });
        }
      });
      if (navigator.mediaDevices) {
        result.issues.push({ type: 'media_devices_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectNotificationAbuse() {
    const result = { issues: [] };
    try {
      if ('Notification' in window) {
        result.issues.push({ type: 'notification_api_available', permission: Notification.permission });
      }
    } catch (e) {}
    return result;
  }

  deepDetectPaymentAPIs() {
    const result = { issues: [] };
    try {
      if (window.PaymentRequest) {
        result.issues.push({ type: 'payment_request_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectCredentialAPIs() {
    const result = { issues: [] };
    try {
      if (navigator.credentials) {
        result.issues.push({ type: 'credentials_api_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectBluetoothUSB() {
    const result = { issues: [] };
    try {
      if (navigator.bluetooth) result.issues.push({ type: 'bluetooth_api_available' });
      if (navigator.usb) result.issues.push({ type: 'usb_api_available' });
    } catch (e) {}
    return result;
  }

  deepDetectShadowDOM() {
    const result = { count: 0, issues: [] };
    try {
      document.querySelectorAll('*').forEach(el => {
        if (el.shadowRoot) {
          result.count++;
        }
      });
      if (result.count > 0) {
        result.issues.push({ type: 'shadow_dom_elements', count: result.count });
      }
    } catch (e) {}
    return result;
  }

  deepDetectWebWorkers() {
    const result = { available: false, issues: [] };
    try {
      if ('Worker' in window) {
        result.available = true;
        const scripts = document.querySelectorAll('script:not([src])');
        scripts.forEach(script => {
          if (script.textContent.includes('new Worker')) {
            result.issues.push({ type: 'inline_worker_creation' });
          }
        });
      }
    } catch (e) {}
    return result;
  }

  deepDetectWebAssembly() {
    const result = { available: false, issues: [] };
    try {
      if (window.WebAssembly) {
        result.available = true;
        result.issues.push({ type: 'webassembly_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectDNSPrefetch() {
    const result = { domains: [], issues: [] };
    try {
      document.querySelectorAll('link[rel="dns-prefetch"]').forEach(link => {
        result.domains.push(link.href);
      });
      if (result.domains.length > 10) {
        result.issues.push({ type: 'excessive_dns_prefetch', count: result.domains.length });
      }
    } catch (e) {}
    return result;
  }

  deepDetectPreconnect() {
    const result = { domains: [], issues: [] };
    try {
      document.querySelectorAll('link[rel="preconnect"]').forEach(link => {
        result.domains.push(link.href);
      });
    } catch (e) {}
    return result;
  }

  deepDetectLinkPrefetch() {
    const result = { links: [], issues: [] };
    try {
      document.querySelectorAll('link[rel="prefetch"], link[rel="preload"]').forEach(link => {
        result.links.push({ href: link.href, as: link.getAttribute('as') || '' });
      });
    } catch (e) {}
    return result;
  }

  deepAnalyzeHTTPRedirects() {
    const result = { issues: [] };
    try {
      if (window.location.href !== window.location.origin + window.location.pathname) {
        result.issues.push({ type: 'url_params_present', params: window.location.search });
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeContentTypes() {
    const result = { issues: [] };
    try {
      const meta = document.querySelector('meta[http-equiv="Content-Type"]');
      if (meta) {
        const content = meta.getAttribute('content') || '';
        if (!content.includes('charset')) {
          result.issues.push({ type: 'missing_charset' });
        }
      }
    } catch (e) {}
    return result;
  }

  deepAnalyzeInputValidation() {
    const result = { inputs: [], issues: [] };
    try {
      document.querySelectorAll('input').forEach(input => {
        const info = {
          type: input.type || 'text',
          name: input.name || '',
          required: input.required,
          pattern: input.pattern || '',
          maxLength: input.maxLength > 0 ? input.maxLength : null
        };
        result.inputs.push(info);
        if (input.type === 'password' && !input.required) {
          result.issues.push({ type: 'password_not_required', name: input.name });
        }
        if (input.type === 'email' && !input.pattern && !input.type) {
          result.issues.push({ type: 'email_no_validation', name: input.name });
        }
      });
    } catch (e) {}
    return result;
  }

  deepAnalyzeAutocomplete() {
    const result = { issues: [] };
    try {
      document.querySelectorAll('input[type="password"], input[type="email"]').forEach(input => {
        const autocomplete = input.getAttribute('autocomplete');
        if (autocomplete === 'on' || !autocomplete) {
          result.issues.push({ type: 'sensitive_autocomplete', name: input.name, type: input.type });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectExternalFonts() {
    const result = { fonts: [], issues: [] };
    try {
      document.querySelectorAll('link[href*="fonts.googleapis.com"], link[href*="fonts.gstatic.com"]').forEach(link => {
        result.fonts.push(link.href);
      });
      document.querySelectorAll('link[href*="typekit"], link[href*="fonts.com"]').forEach(link => {
        result.fonts.push(link.href);
      });
      if (result.fonts.length > 5) {
        result.issues.push({ type: 'excessive_external_fonts', count: result.fonts.length });
      }
    } catch (e) {}
    return result;
  }

  deepDetectExternalStyles() {
    const result = { stylesheets: [], issues: [] };
    try {
      document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
        try {
          const url = new URL(link.href, window.location.href);
          if (url.hostname !== window.location.hostname) {
            result.stylesheets.push(url.href);
          }
        } catch (e) {}
      });
    } catch (e) {}
    return result;
  }

  deepAnalyzeIframeSandbox() {
    const result = { iframes: [], issues: [] };
    try {
      document.querySelectorAll('iframe').forEach(iframe => {
        const info = {
          src: iframe.src?.substring(0, 200) || '',
          sandbox: iframe.sandbox?.value || '',
          hasSandbox: iframe.hasAttribute('sandbox')
        };
        result.iframes.push(info);
        if (!info.hasSandbox && info.src && !info.src.startsWith('about:')) {
          result.issues.push({ type: 'unsandboxed_iframe', src: info.src });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectObjectEmbed() {
    const result = { count: 0, issues: [] };
    try {
      result.count = document.querySelectorAll('object, embed').length;
      if (result.count > 0) {
        result.issues.push({ type: 'object_embed_detected', count: result.count });
      }
    } catch (e) {}
    return result;
  }

  deepDetectApplets() {
    const result = { count: 0, issues: [] };
    try {
      result.count = document.querySelectorAll('applet').length;
      if (result.count > 0) {
        result.issues.push({ type: 'java_applet_detected', count: result.count });
      }
    } catch (e) {}
    return result;
  }

  deepDetectDataExfiltration() {
    const result = { issues: [], patterns: [] };
    try {
      const exfilRegexes = [
        { re: /navigator\.sendBeacon/g, name: 'sendBeacon' },
        { re: /new\s+Image\(\).*\.src\s*=/g, name: 'pixel_tracking' },
        { re: /XMLHttpRequest.*open\s*\(\s*['"]POST['"]/g, name: 'xhr_post' },
        { re: /fetch\s*\(.*method\s*:\s*['"]POST['"]/g, name: 'fetch_post' },
        { re: /navigator\.sendBeacon.*data\s*:/g, name: 'beacon_with_data' }
      ];
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        const seen = new Set();
        exfilRegexes.forEach(({ re, name }) => {
          re.lastIndex = 0;
          if (re.test(content) && !seen.has(name)) {
            result.patterns.push(name);
            seen.add(name);
          }
        });
      });
      if (result.patterns.length > 0) {
        result.issues.push({ type: 'data_exfil_patterns', patterns: result.patterns.slice(0, 20) });
      }
    } catch (e) {}
    return result;
  }

  deepDetectKeylogging() {
    const result = { issues: [], patterns: [] };
    try {
      const keyRegexes = [
        { re: /addEventListener\s*\(\s*['"]keydown['"]/g, name: 'keydown_listener' },
        { re: /addEventListener\s*\(\s*['"]keypress['"]/g, name: 'keypress_listener' },
        { re: /addEventListener\s*\(\s*['"]keyup['"]/g, name: 'keyup_listener' },
        { re: /onkeydown|onkeypress|onkeyup/g, name: 'inline_key_handler' }
      ];
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        const seen = new Set();
        keyRegexes.forEach(({ re, name }) => {
          re.lastIndex = 0;
          if (re.test(content) && !seen.has(name)) {
            result.patterns.push(name);
            seen.add(name);
          }
        });
      });
      if (result.patterns.length > 2) {
        result.issues.push({ type: 'potential_keylogging', patterns: result.patterns.slice(0, 10) });
      }
    } catch (e) {}
    return result;
  }

  deepDetectFormjacking() {
    const result = { issues: [], forms: [] };
    try {
      document.querySelectorAll('form').forEach(form => {
        const action = form.action || '';
        const method = (form.method || 'get').toLowerCase();
        const formInfo = { action: action.substring(0, 200), method, fields: form.querySelectorAll('input').length };
        result.forms.push(formInfo);
        if (method === 'get' && form.querySelectorAll('input[type="password"]').length > 0) {
          result.issues.push({ type: 'password_in_get_form', action: formInfo.action });
        }
        if (action.startsWith('http://')) {
          result.issues.push({ type: 'insecure_form_action', action: formInfo.action });
        }
        try {
          const url = new URL(action, window.location.href);
          if (url.hostname !== window.location.hostname && !action.startsWith('/')) {
            result.issues.push({ type: 'cross_origin_form', action: formInfo.action, host: url.hostname });
          }
        } catch (e) {}
      });
    } catch (e) {}
    return result;
  }

  deepDetectMagecart() {
    const result = { issues: [], patterns: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        const magecartPatterns = [
          { pattern: /\.value\s*=\s*.*card.*number/i, name: 'card_number_access' },
          { pattern: /getElementById\s*\(\s*['"]ccnum/i, name: 'card_element_access' },
          { pattern: /\.addEventListener\s*\(\s*['"]submit['"].*card/i, name: 'form_submit_capture' },
          { pattern: /fetch\s*\(.*payment.*card/i, name: 'payment_data_exfil' }
        ];
        magecartPatterns.forEach(({ pattern, name }) => {
          if (pattern.test(content)) {
            result.patterns.push(name);
          }
        });
      });
      if (result.patterns.length > 0) {
        result.issues.push({ type: 'potential_formjacking', patterns: result.patterns.slice(0, 10) });
      }
    } catch (e) {}
    return result;
  }

  deepDetectSessionFixation() {
    const result = { issues: [] };
    try {
      const cookies = document.cookie.split(';').filter(c => c.trim());
      cookies.forEach(cookie => {
        const name = cookie.split('=')[0].trim().toLowerCase();
        if (name === 'sessionid' || name === 'jsessionid' || name === 'phpsessid' || name === 'asp.net_sessionid' || name === 'connect.sid') {
          result.issues.push({ type: 'session_cookie_detected', name, note: 'Cannot verify Secure/SameSite flags from JavaScript' });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectCSRF() {
    const result = { issues: [], hasCsrfToken: false };
    try {
      document.querySelectorAll('form').forEach(form => {
        const tokens = form.querySelectorAll('input[name*="csrf"], input[name*="token"], input[name="_token"], input[name="csrf_token"], input[name="authenticity_token"]');
        if (tokens.length > 0) result.hasCsrfToken = true;
      });
      document.querySelectorAll('meta[name="csrf-token"]').forEach(() => { result.hasCsrfToken = true; });
      if (!result.hasCsrfToken) {
        const forms = document.querySelectorAll('form[method="post"], form[method="POST"]');
        if (forms.length > 0) {
          result.issues.push({ type: 'no_csrf_token', formCount: forms.length });
        }
      }
    } catch (e) {}
    return result;
  }

  deepDetectOpenRedirects() {
    const result = { issues: [] };
    try {
      const params = new URLSearchParams(window.location.search);
      const redirectParams = ['redirect', 'url', 'next', 'return', 'goto', 'continue', 'dest', 'destination', 'redir', 'return_to', 'checkout_url', 'return_url'];
      redirectParams.forEach(param => {
        if (params.has(param)) {
          const value = params.get(param) || '';
          if (value.startsWith('http://') || value.startsWith('//') || value.includes('://')) {
            result.issues.push({ type: 'potential_open_redirect', param, value: value.substring(0, 200) });
          }
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectPathTraversal() {
    const result = { issues: [] };
    try {
      if (window.location.pathname.includes('..') || window.location.pathname.includes('%2e%2e')) {
        result.issues.push({ type: 'path_traversal_in_url' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectSQLInjectionPatterns() {
    const result = { issues: [] };
    try {
      const params = new URLSearchParams(window.location.search);
      const sqlPatterns = [
        { pattern: /union\s+select/i, name: 'union_select' },
        { pattern: /or\s+1\s*=\s*1/i, name: 'or_1_equals_1' },
        { pattern: /;\s*drop\s+table/i, name: 'drop_table' },
        { pattern: /'\s*or\s+''/i, name: 'or_empty_string' },
        { pattern: /--\s*$/, name: 'sql_comment' },
        { pattern: /\/\*.*\*\//, name: 'sql_block_comment' }
      ];
      params.forEach((value, key) => {
        sqlPatterns.forEach(({ pattern, name }) => {
          if (pattern.test(value)) {
            result.issues.push({ type: 'sqli_pattern_in_url', param: key, pattern: name });
          }
        });
      });
    } catch (e) {}
    return result;
  }

  deepDetectXXE() {
    const result = { issues: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        const xxePatterns = [
          /DOMParser\s*\(\s*\)\s*\.parseFromString\s*\(/i,
          /new\s+XMLSerializer/i,
          /\.loadXML\s*\(/i
        ];
        xxePatterns.forEach(pattern => {
          if (pattern.test(content)) {
            result.issues.push({ type: 'xml_parsing_detected' });
          }
        });
      });
    } catch (e) {}
    return result;
  }

  deepDetectSSRF() {
    const result = { issues: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        const ssrfPatterns = [
          /fetch\s*\(\s*['"]https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
          /XMLHttpRequest.*open\s*\(\s*['"]GET['"]\s*,\s*['"]https?:\/\/(localhost|127\.0\.0\.1)/i,
          /\$\.get\s*\(\s*['"]https?:\/\/(localhost|127\.0\.0\.1)/i
        ];
        ssrfPatterns.forEach(pattern => {
          if (pattern.test(content)) {
            result.issues.push({ type: 'potential_ssrf_pattern' });
          }
        });
      });
    } catch (e) {}
    return result;
  }

  deepDetectDNSRebinding() {
    const result = { issues: [] };
    try {
      if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        result.issues.push({ type: 'localhost_access', severity: 'info' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectSRI() {
    const result = { total: 0, protected: 0, unprotected: 0, issues: [] };
    try {
      document.querySelectorAll('script[src]').forEach(script => {
        result.total++;
        if (script.integrity) result.protected++;
        else result.unprotected++;
      });
      if (result.unprotected > 5 && result.total > 10) {
        result.issues.push({ type: 'low_sri_coverage', ratio: result.protected / result.total });
      }
    } catch (e) {}
    return result;
  }

  deepDetectMixedProtocol() {
    const result = { issues: [] };
    try {
      if (window.location.protocol === 'https:') {
        document.querySelectorAll('[src], [href]').forEach(el => {
          const url = el.src || el.href || '';
          if (url.startsWith('http://') && !url.startsWith('http://localhost')) {
            result.issues.push({ type: 'mixed_content', tag: el.tagName.toLowerCase(), url: url.substring(0, 200) });
          }
        });
      }
    } catch (e) {}
    return result;
  }

  deepDetectInsecureFormActions() {
    const result = { issues: [] };
    try {
      document.querySelectorAll('form').forEach(form => {
        const action = form.action || '';
        if (action.startsWith('http://') && !action.includes('localhost')) {
          result.issues.push({ type: 'insecure_form_action', action: action.substring(0, 200) });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectAutofillAbuse() {
    const result = { issues: [] };
    try {
      document.querySelectorAll('input[autocomplete="on"], input:not([autocomplete])').forEach(input => {
        if (['password', 'email', 'tel', 'cc-number', 'cc-exp'].includes(input.type)) {
          result.issues.push({ type: 'autofill_enabled', fieldType: input.type, name: input.name });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectFingerprintJS() {
    const result = { issues: [] };
    try {
      const fingerprintDomains = self.__privacyDomains?.fingerprintDomains || [];
      const scripts = this._getAllScriptSources();
      scripts.forEach(src => {
        const lower = src.toLowerCase();
        if (fingerprintDomains.some(d => lower.includes(d)) || lower.includes('fingerprintjs')) {
          result.issues.push({ type: 'fingerprintjs_detected', source: src.substring(0, 200) });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectCanvasFingerprinting() {
    const result = { attempts: this.fingerprintingAttempts.filter(f => f.type.startsWith('canvas')).length, issues: [] };
    try {
      if (result.attempts > 0) {
        result.issues.push({ type: 'canvas_fingerprinting', attempts: result.attempts });
      }
    } catch (e) {}
    return result;
  }

  deepDetectWebGLFingerprinting() {
    const result = { available: !!this.webglInfo, issues: [] };
    try {
      if (this.webglInfo) {
        result.issues.push({ type: 'webgl_fingerprinting_vector', vendor: this.webglInfo.vendor?.substring(0, 100) || '' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectAudioFingerprinting() {
    const result = { attempts: this.fingerprintingAttempts.filter(f => f.type.startsWith('audio')).length, issues: [] };
    try {
      if (result.attempts > 0) {
        result.issues.push({ type: 'audio_fingerprinting', attempts: result.attempts });
      }
    } catch (e) {}
    return result;
  }

  deepDetectFontFingerprinting() {
    const result = { attempts: this.fingerprintingAttempts.filter(f => f.type.includes('font')).length, issues: [] };
    try {
      if (result.attempts > 0) {
        result.issues.push({ type: 'font_fingerprinting', attempts: result.attempts });
      }
    } catch (e) {}
    return result;
  }

  deepDetectScreenFingerprinting() {
    const result = { info: {}, issues: [] };
    try {
      result.info = {
        width: screen.width, height: screen.height,
        availWidth: screen.availWidth, availHeight: screen.availHeight,
        colorDepth: screen.colorDepth, pixelDepth: screen.pixelDepth
      };
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if ((content.includes('screen.width') || content.includes('screen.height') || content.includes('screen.colorDepth')) && content.length > 100) {
          result.issues.push({ type: 'screen_fingerprinting' });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectNavigatorFingerprinting() {
    const result = { info: {}, issues: [] };
    try {
      result.info = {
        userAgent: navigator.userAgent?.substring(0, 150) || '',
        language: navigator.language,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        maxTouchPoints: navigator.maxTouchPoints,
        deviceMemory: navigator.deviceMemory
      };
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if ((content.includes('navigator.userAgent') || content.includes('navigator.platform') || content.includes('navigator.language')) && content.length > 100) {
          result.issues.push({ type: 'navigator_fingerprinting' });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectBatteryAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('getBattery' in navigator) {
        result.available = true;
        result.issues.push({ type: 'battery_api_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectConnectionAPI() {
    const result = { info: {}, issues: [] };
    try {
      const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
      if (conn) {
        result.info = { type: conn.effectiveType, downlink: conn.downlink, rtt: conn.rtt };
        result.issues.push({ type: 'connection_api_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectSpeechRecognition() {
    const result = { available: false, issues: [] };
    try {
      if ('SpeechRecognition' in window || 'webkitSpeechRecognition' in window) {
        result.available = true;
        result.issues.push({ type: 'speech_recognition_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectVRAR() {
    const result = { available: false, issues: [] };
    try {
      if ('xr' in navigator) {
        result.available = true;
        result.issues.push({ type: 'webxr_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectNFC() {
    const result = { available: false, issues: [] };
    try {
      if ('NDEFReader' in window) {
        result.available = true;
        result.issues.push({ type: 'webnfc_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectGamepadAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('getGamepads' in navigator) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectSerialAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('serial' in navigator) {
        result.available = true;
        result.issues.push({ type: 'webserial_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectUSBDeviceAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('usb' in navigator) {
        result.available = true;
        result.issues.push({ type: 'webusb_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectHID() {
    const result = { available: false, issues: [] };
    try {
      if ('hid' in navigator) {
        result.available = true;
        result.issues.push({ type: 'webhid_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectWakeLock() {
    const result = { available: false, issues: [] };
    try {
      if ('wakeLock' in navigator) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectPresentationAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('presentation' in navigator) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectBackgroundSync() {
    const result = { available: false, issues: [] };
    try {
      if ('serviceWorker' in navigator && 'SyncManager' in window) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectPushAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('serviceWorker' in navigator && 'PushManager' in window) {
        result.available = true;
        result.issues.push({ type: 'push_api_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectPeriodicSync() {
    const result = { available: false, issues: [] };
    try {
      if ('serviceWorker' in navigator && 'PeriodicSyncManager' in window) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectContentIndexing() {
    const result = { available: false, issues: [] };
    try {
      if ('serviceWorker' in navigator && 'ContentIndex' in window) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectShareAPI() {
    const result = { available: false, issues: [] };
    try {
      if (navigator.share) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectContactsAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('contacts' in navigator && 'ContactsManager' in window) {
        result.available = true;
        result.issues.push({ type: 'contacts_api_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectCredentialsAPI() {
    const result = { available: false, issues: [] };
    try {
      if (navigator.credentials) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectWebShare() {
    const result = { available: false, issues: [] };
    try {
      if (navigator.canShare) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectFileSystemAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('requestFileSystem' in window || 'webkitRequestFileSystem' in window) {
        result.available = true;
        result.issues.push({ type: 'filesystem_api_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectStorageAPI() {
    const result = { available: false, persistent: false, issues: [] };
    try {
      if ('storage' in navigator && 'estimate' in navigator.storage) {
        result.available = true;
        navigator.storage.estimate().then(est => {
          result.usage = est.usage;
          result.quota = est.quota;
        }).catch(() => {});
        if ('persist' in navigator.storage) {
          navigator.storage.persist().then(p => { result.persistent = p; }).catch(() => {});
        }
      }
    } catch (e) {}
    return result;
  }

  deepDetectPermissionStatus() {
    const result = { permissions: [], issues: [] };
    try {
      if (navigator.permissions) {
        const perms = ['camera', 'microphone', 'geolocation', 'notifications', 'midi', 'push'];
        perms.forEach(p => {
          navigator.permissions.query({ name: p }).then(status => {
            result.permissions.push({ name: p, state: status.state });
          }).catch(() => {});
        });
      }
    } catch (e) {}
    return result;
  }

  deepDetectClipboardRead() {
    const result = { available: false, issues: [] };
    try {
      if (navigator.clipboard && navigator.clipboard.readText) {
        result.available = true;
        result.issues.push({ type: 'clipboard_read_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectClipboardWrite() {
    const result = { available: false, issues: [] };
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectMediaRecorder() {
    const result = { available: false, issues: [] };
    try {
      if ('MediaRecorder' in window) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectImageCapture() {
    const result = { available: false, issues: [] };
    try {
      if ('ImageCapture' in window) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectBarcodeDetector() {
    const result = { available: false, issues: [] };
    try {
      if ('BarcodeDetector' in window) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectFaceDetection() {
    const result = { available: false, issues: [] };
    try {
      if ('FaceDetector' in window) {
        result.available = true;
        result.issues.push({ type: 'face_detection_api_available' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectTextDetection() {
    const result = { available: false, issues: [] };
    try {
      if ('TextDetector' in window) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectStyleDetection() {
    const result = { issues: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('getComputedStyle') && content.includes('font')) {
          result.issues.push({ type: 'computed_style_font_check' });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectCookieSync() {
    const result = { issues: [] };
    try {
      const domains = self.__privacyDomains || {};
      const syncDomains = [
        ...(domains.adNetworks || []).slice(0, 10),
        ...(domains.socialDomains || []).slice(0, 5)
      ];
      const iframes = document.querySelectorAll('iframe');
      let syncCount = 0;
      iframes.forEach(iframe => {
        const src = iframe.src || '';
        if (syncDomains.some(d => src.includes(d))) {
          syncCount++;
        }
      });
      if (syncCount > 0) {
        result.issues.push({ type: 'cookie_sync_iframes', count: syncCount });
      }
    } catch (e) {}
    return result;
  }

  deepDetectEvercookies() {
    const result = { issues: [] };
    try {
      const scripts = this._getAllScriptSources();
      scripts.forEach(src => {
        const lower = src.toLowerCase();
        if (lower.includes('evercookie')) {
          result.issues.push({ type: 'evercookie_detected', source: src.substring(0, 200) });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectCacheTiming() {
    const result = { issues: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('getComputedStyle') && (content.includes('visited') || content.includes(':visited'))) {
          result.issues.push({ type: 'cache_timing_attack' });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectHistorySniffing() {
    const result = { issues: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('history.length') && content.length > 100) {
          result.issues.push({ type: 'history_sniffing' });
        }
      });
    } catch (e) {}
    return result;
  }

  deepDetectPluginEnumeration() {
    const result = { count: 0, issues: [] };
    try {
      result.count = navigator.plugins?.length || 0;
      if (result.count > 0) {
        result.issues.push({ type: 'plugin_enumeration_vector', count: result.count });
      }
    } catch (e) {}
    return result;
  }

  deepDetectMimeTypeEnumeration() {
    const result = { count: 0, issues: [] };
    try {
      result.count = navigator.mimeTypes?.length || 0;
    } catch (e) {}
    return result;
  }

  deepDetectMediaDevices() {
    const result = { available: false, issues: [] };
    try {
      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        result.available = true;
        navigator.mediaDevices.enumerateDevices().then(devices => {
          result.deviceCount = devices.length;
          result.hasCamera = devices.some(d => d.kind === 'videoinput');
          result.hasMicrophone = devices.some(d => d.kind === 'audioinput');
        }).catch(() => {});
      }
    } catch (e) {}
    return result;
  }

  deepDetectSpeechSynthesis() {
    const result = { available: false, voices: 0, issues: [] };
    try {
      if ('speechSynthesis' in window) {
        result.available = true;
        result.voices = window.speechSynthesis.getVoices().length;
      }
    } catch (e) {}
    return result;
  }

  deepDetectSpeechRecognitionAPI() {
    const result = { available: false, issues: [] };
    try {
      if ('SpeechRecognition' in window || 'webkitSpeechRecognition' in window) {
        result.available = true;
        result.issues.push({ type: 'speech_recognition_api' });
      }
    } catch (e) {}
    return result;
  }

  deepDetectMIDI() {
    const result = { available: false, issues: [] };
    try {
      if (navigator.requestMIDIAccess) {
        result.available = true;
      }
    } catch (e) {}
    return result;
  }

  deepDetectSensorAPIs() {
    const result = { sensors: [], issues: [] };
    try {
      if ('Accelerometer' in window) result.sensors.push('accelerometer');
      if ('Gyroscope' in window) result.sensors.push('gyroscope');
      if ('Magnetometer' in window) result.sensors.push('magnetometer');
      if ('LinearAccelerationSensor' in window) result.sensors.push('linear_acceleration');
      if ('AbsoluteOrientationSensor' in window) result.sensors.push('absolute_orientation');
      if ('RelativeOrientationSensor' in window) result.sensors.push('relative_orientation');
      if ('AmbientLightSensor' in window) result.sensors.push('ambient_light');
      if (result.sensors.length > 0) {
        result.issues.push({ type: 'sensor_apis_available', sensors: result.sensors });
      }
    } catch (e) {}
    return result;
  }

  deepDetectMutationObservers() {
    const result = { count: 0, issues: [] };
    try {
      const origMO = window.MutationObserver;
      let observerCount = 0;
      window.MutationObserver = function(...args) {
        observerCount++;
        return new origMO(...args);
      };
      window.MutationObserver.prototype = origMO.prototype;
      setTimeout(() => {
        window.MutationObserver = origMO;
        result.count = observerCount;
      }, 1000);
    } catch (e) {}
    return result;
  }

  deepDetectTimerAbuse() {
    const result = { issues: [], patterns: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        const setTimeoutCount = (content.match(/setTimeout/g) || []).length;
        const setIntervalCount = (content.match(/setInterval/g) || []).length;
        if (setTimeoutCount > 10) result.patterns.push('excessive_setTimeout');
        if (setIntervalCount > 5) result.patterns.push('excessive_setInterval');
        if (content.includes('requestAnimationFrame') && content.includes('data')) {
          result.patterns.push('raf_data_collection');
        }
      });
      if (result.patterns.length > 0) {
        result.issues.push({ type: 'timer_abuse', patterns: result.patterns.slice(0, 10) });
      }
    } catch (e) {}
    return result;
  }

  deepDetectWorkerSpam() {
    const result = { issues: [], workers: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('new Worker(') || content.includes('new SharedWorker(')) {
          result.workers.push({ type: content.includes('SharedWorker') ? 'shared' : 'dedicated' });
        }
      });
      if (result.workers.length > 3) {
        result.issues.push({ type: 'excessive_workers', count: result.workers.length });
      }
    } catch (e) {}
    return result;
  }

  deepDetectCryptoMiningExpanded() {
    const result = { miners: [], issues: [] };
    try {
      const patterns = self.__privacyDomains?.cryptominingPatterns || [];
      const scripts = this._getAllScriptSources();
      scripts.forEach(src => {
        const lower = src.toLowerCase();
        patterns.forEach(pattern => {
          if (lower.includes(pattern.toLowerCase())) {
            result.miners.push({ pattern, source: src.substring(0, 200) });
          }
        });
      });
      if (result.miners.length > 0) {
        result.issues.push({ type: 'cryptomining_expanded', count: result.miners.length });
      }
    } catch (e) {}
    return result;
  }

  deepDetectAdInjection() {
    const result = { issues: [], patterns: [] };
    try {
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(script => {
        const content = script.textContent || '';
        if (content.includes('document.createElement("iframe")') || content.includes("document.createElement('iframe')")) {
          result.patterns.push('dynamic_iframe_creation');
        }
        if (content.includes('innerHTML') && (content.includes('ad') || content.includes('banner'))) {
          result.patterns.push('ad_innerhtml_injection');
        }
        if (content.includes('window.open') && content.includes('ad')) {
          result.patterns.push('ad_popup');
        }
      });
      if (result.patterns.length > 0) {
        result.issues.push({ type: 'ad_injection_patterns', patterns: result.patterns.slice(0, 10) });
      }
    } catch (e) {}
    return result;
  }

  deepDetectAffiliateTracking() {
    const result = { issues: [], patterns: [] };
    try {
      const params = new URLSearchParams(window.location.search);
      const affiliateParams = ['ref', 'affiliate', 'partner', 'campaign', 'utm_source', 'utm_medium', 'utm_campaign', 'click_id', 'sub_id', 'offer_id'];
      affiliateParams.forEach(param => {
        if (params.has(param)) {
          result.patterns.push(param);
        }
      });
      if (result.patterns.length > 0) {
        result.issues.push({ type: 'affiliate_tracking_params', params: result.patterns.slice(0, 10) });
      }
    } catch (e) {}
    return result;
  }

  deepDetectAdvancedFingerprinting() {
    const result = { vectors: [], issues: [] };
    try {
      result.vectors.push({ type: 'canvas', available: !!document.createElement('canvas').getContext });
      result.vectors.push({ type: 'webgl', available: !!(document.createElement('canvas').getContext('webgl') || document.createElement('canvas').getContext('experimental-webgl')) });
      result.vectors.push({ type: 'audio', available: !!(window.AudioContext || window.webkitAudioContext) });
      result.vectors.push({ type: 'fonts', available: document.fonts?.check?.('16px monospace') !== undefined });
      result.vectors.push({ type: 'screen', available: !!window.screen });
      result.vectors.push({ type: 'navigator', available: !!window.navigator });
      result.vectors.push({ type: 'timezone', available: !!Intl.DateTimeFormat });
      result.vectors.push({ type: 'webrtc', available: !!(window.RTCPeerConnection || window.webkitRTCPeerConnection) });
      result.vectors.push({ type: 'battery', available: 'getBattery' in navigator });
      result.vectors.push({ type: 'connection', available: !!(navigator.connection || navigator.mozConnection || navigator.webkitConnection) });
      result.vectors.push({ type: 'speech', available: !!(window.SpeechRecognition || window.webkitSpeechRecognition) });
      result.vectors.push({ type: 'gamepad', available: 'getGamepads' in navigator });
      result.vectors.push({ type: 'serial', available: 'serial' in navigator });
      result.vectors.push({ type: 'usb', available: 'usb' in navigator });
      result.vectors.push({ type: 'hid', available: 'hid' in navigator });
      result.vectors.push({ type: 'bluetooth', available: 'bluetooth' in navigator });
      const availableCount = result.vectors.filter(v => v.available).length;
      if (availableCount > 10) {
        result.issues.push({ type: 'high_fingerprint_surface', vectors: availableCount });
      }
    } catch (e) {}
    return result;
  }

  _isTrackingKey(key) {
    const patterns = self.__privacyDomains?.trackingCookiePatterns || [];
    return patterns.some(p => key.toLowerCase().includes(p.toLowerCase()));
  }
}

const __analyzer = new ComprehensiveWebsiteAnalyzer();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getScanResults') {
    sendResponse(__analyzer.getScanResults());
  }
  return true;
});
