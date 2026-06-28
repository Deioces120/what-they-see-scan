const SCORING = {
  popup: {
    base: 40,
    https: { bonus: 15, penalty: -25 },
    forms: { secure: 5, insecure: -15 },
    thirdParty: { low: 5, mid: 2, high: -5, veryHigh: -10 },
    cookies: { none: 5, low: 2, high: -5, veryHigh: -10 },
    headers: { csp: 10, hsts: 5, xFrame: 3, xContent: 2 },
    perPixel: -3, perFingerprint: -8, perMiner: -25, perAd: -2, perSocial: -2,
    deepScan: {
      cspBonus: 3, mixedContent: -3, sri: -5,
      xssLow: -3, xssHigh: -8,
      keylogLow: -5, keylogHigh: -12,
      formjacking: -10, magecart: -15, cryptoMiners: -25,
      cookieTrackLow: -2, cookieTrackHigh: -5,
      domVulnLow: -3, domVulnHigh: -10,
      dataExfilLow: -3, dataExfilHigh: -10,
      adInjection: -5, sessionFixation: -8, csrf: -5, openRedirect: -5,
      evercookies: -10, cacheTiming: -5, historySniffing: -3,
      mediaAccess: -3, geolocation: -5, clipboard: -5,
      fingerprint2: -8, canvas2Low: -3, canvas2High: -5,
      audio2Low: -2, audio2High: -5,
      font2: -3, screen2: -3, navigator2: -3, cryptoMining: -15,
      workerSpam: -5, fingerprint3Low: -3, fingerprint3High: -8,
      permissions: -2, autofill: -3, shadowDOM: -3, webWorkers: -3,
      bluetoothUSB: -3
    },
    network: { tracking: -3, ad: -2, social: -1, analytics: -1, domainExtra: -2, domainThreshold: 5 }
  },
  privacy: {
    base: 100,
    perTracking: -4, perAd: -3, perMalicious: -20,
    domainExtra: -2, domainThreshold: 10, perSensitive: -5,
    perPixel: -5, perFingerprint: -10, perMiner: -25,
    https: { bonus: 5, penalty: -20 },
    thirdParty: { penalty: -2, threshold: 5 },
    deepScan: {
      cryptoMiners: -20, keylog: -15, formjacking: -15, magecart: -20,
      dataExfil: -10, xss: -5, evercookies: -15, clipboard: -5,
      geolocation: -5, mediaAccess: -3, fingerprint3: -2, cookieTrack: -2,
      adInjection: -5, shadowDOM: -1, workerSpam: -2, bluetoothUSB: -2,
      contacts: -5, faceDetection: -5
    }
  },
  security: {
    base: 50,
    https: { bonus: 30, penalty: -40 },
    headers: { csp: 20, hsts: 15, xFrame: 10, xContent: 5 },
    forms: { insecure: -25, secure: 10 },
    perMalicious: -30,
    deepScan: {
      cspBonus: 5, mixedContent: -3, sri: -5, xss: -5, domVuln: -5,
      sessionFixation: -8, csrf: -5, openRedirect: -3, keylog: -10,
      formjacking: -8, magecart: -15, cryptoMiners: -25, adInjection: -3
    }
  },
  threatModels: {
    advertising: { tracking: 2.0, ads: 2.0, cookies: 2.0, pixel: 1.5, fingerprint: 1.5 },
    surveillance: { fingerprint: 2.0, geolocation: 2.0, clipboard: 2.0, mediaAccess: 2.0 },
    financial: { https: 2.0, headers: 2.0, forms: 2.0, cryptoMiners: 2.0, formjacking: 2.0, magecart: 2.0 }
  }
};
