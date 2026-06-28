self.__privacyDomains = {
  trackingDomains: [
    'google-analytics.com', 'googletagmanager.com', 'ga.jspm.io',
    'hotjar.com', 'crazyegg.com', 'mouseflow.com', 'fullstory.com',
    'logrocket.com', 'amplitude.com', 'mixpanel.com', 'segment.com',
    'facebook.com', 'facebook.net', 'fbcdn.net', 'instagram.com',
    'twitter.com', 'linkedin.com', 'pinterest.com', 'tiktok.com',
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'amazon-adsystem.com', 'outbrain.com', 'taboola.com', 'criteo.com', 'media.net',
    'branch.io', 'adjust.com', 'appsflyer.com', 'singular.net',
    'newrelic.com', 'sentry.io', 'datadoghq.com', 'bugsnag.com',
    'pubmatic.com', 'rubiconproject.com', 'openx.net', 'adnxs.com',
    'casalemedia.com', 'indexexchange.com', 'sharethrough.com',
    'teads.tv', 'moat.com', 'adsrvr.org', 'demdex.net',
    'everesttech.net', 'bluekai.com', 'lotame.com', 'krxd.net',
    'quantserve.com', 'scorecardresearch.com', 'chartbeat.com',
    'optimizely.com', 'heap.io', 'pendo.io', 'kissmetrics.com'
  ],
  maliciousDomains: [
    'coinhive.com', 'coin-hive.com', 'authedmine.com', 'crypto-loot.com',
    'webminerpool.com', 'jsecoin.com', 'minergate.com', 'deepminer.net',
    'coinimp.com', 'ppoi.org', 'monerominer.rocks', 'webminepool.com',
    'miner.pr0gramm.com', 'minr.pw', 'webmr.cryptaloot.pro'
  ],
  adNetworks: [
    'googlesyndication.com', 'doubleclick.net', 'googleadservices.com',
    'amazon-adsystem.com', 'outbrain.com', 'taboola.com',
    'criteo.com', 'media.net', 'pubmatic.com', 'rubiconproject.com',
    'openx.net', 'adnxs.com', 'casalemedia.com', 'indexexchange.com',
    'sharethrough.com', 'teads.tv', 'spotxchange.com', 'moat.com',
    'adsrvr.org', 'demdex.net', 'everesttech.net', 'bluekai.com',
    'lotame.com', 'krxd.net', 'bombora.com', 'zoominfo.com',
    'quantserve.com', 'scorecardresearch.com', 'chartbeat.com',
    'optimizely.com', 'branch.io', 'adjust.com', 'appsflyer.com',
    'bidswitch.net', 'rlcdn.com', 'mathtag.com', 'turn.com', 'moatads.com', 'prebid.org'
  ],
  socialDomains: [
    'facebook.com', 'facebook.net', 'fbcdn.net', 'twitter.com',
    'instagram.com', 'linkedin.com', 'pinterest.com', 'tiktok.com',
    'youtube.com', 'snapchat.com', 'reddit.com', 'tumblr.com',
    't.co', 'twimg.com', 'cdninstagram.com', 'licdn.com',
    'youtu.be', 'ytimg.com', 'pinimg.com', 'tiktokcdn.com'
  ],
  analyticsDomains: [
    'google-analytics.com', 'googletagmanager.com', 'hotjar.com', 'mixpanel.com',
    'segment.com', 'amplitude.com', 'crazyegg.com', 'fullstory.com',
    'optimizely.com', 'heap.io', 'pendo.io', 'kissmetrics.com',
    'newrelic.com', 'sentry.io', 'datadoghq.com', 'bugsnag.com'
  ],
  essentialDomains: [
    'cloudflare.com', 'amazonaws.com', 'cloudfront.net', 'jsdelivr.net',
    'unpkg.com', 'cdnjs.cloudflare.com', 'googleapis.com', 'gstatic.com',
    'github.io', 'azure.com', 'fastly.net'
  ],
  cdnDomains: [
    'akamai.net', 'akamaized.net', 'fastly.net', 'azureedge.net',
    'edgecastcdn.net', 'maxcdn.com', 'bootstrapcdn.com'
  ],
  cryptominingPatterns: [
    'coinhive', 'jsecoin', 'coinerra', 'minergate', 'crypto-loot',
    'webminerpool', 'coin-have', 'minero', 'cryptonight', 'cryptonoter',
    'authedmine', 'coinimp', 'ppoi.org', 'monerominer.rocks',
    'webminepool.com', 'miner.pr0gramm.com', 'minr.pw', 'webmr.cryptaloot.pro',
    'coinpirate', 'xmrig', 'monero', 'cryptojack'
  ],
  trackingCookiePatterns: [
    '_ga', '_gid', '_gat', '_fbp', '_fbc', '_hjid', '__utma', 'utm_',
    '_clck', '_pk_', '_fbp_', 'fr', 'IDE', 'NID', '1p_jar', 'CONSENT',
    'GPS', 'VISITOR_INFO1', 'YSC', 'S', 'SID', 'HSID', 'SSID',
    'APISID', 'SAPISID', '_uetsid', '_uetvid', '1P_JAR'
  ],
  sensitiveDataPatterns: [
    'password', 'creditcard', 'ssn', 'social-security', 'bank-account',
    'routing-number', 'tax-id', 'passport', 'driver-license', 'medical',
    'health', 'insurance', 'date-of-birth', 'birth-date'
  ],
  fingerprintingPatterns: [
    'fingerprint', 'canvas', 'webgl', 'audio', 'font',
    'navigator.', 'screen.', 'timezone', 'language', 'platform'
  ],
  socialWidgetSelectors: [
    '.fb-like', '.fb-share-button', '.twitter-share-button',
    '.linkedin-share-button', '.pinterest-share-button'
  ],
  fingerprintDomains: ['fingerprint.com', 'fpjs.io'],
  malwareDomains: [
    'coinhive.com', 'coin-hive.com', 'authedmine.com', 'crypto-loot.com',
    'webminerpool.com', 'jsecoin.com', 'minergate.com', 'deepminer.net',
    'coinimp.com'
  ]
};
