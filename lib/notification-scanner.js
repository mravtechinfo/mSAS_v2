/**
 * mSAS v2 — Push Notification Leakage Scanner
 * MASTG Ref: MASTG-STORAGE-8 (Notification Data Leakage)
 * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 */

var MSAS = MSAS || {};
MSAS.NotificationScanner = (function() {
  'use strict';

  var CWE = 'CWE-200';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-8';

  var NOTIFICATION_SIGS = [
    'Landroid/app/NotificationManager',
    'Landroid/app/NotificationChannel',
    'Landroid/app/Notification$Builder',
    'NotificationCompat$Builder',
    'Landroidx/core/app/NotificationCompat',
    'notify',
    'NotificationManager'
  ];

  var FCM_SIGS = [
    'Lcom/google/firebase/messaging/FirebaseMessagingService',
    'Lcom/google/firebase/messaging/RemoteMessage',
    'onMessageReceived',
    'FirebaseMessagingService'
  ];

  var SENSITIVE_NOTIFICATION_SIGS = [
    'setContentText',
    'setTicker',
    'setContentTitle',
    'setContentIntent'
  ];
  // Note: method names stored without parentheses in DEX string pool

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasNotification = MSAS.Utils.hasInStrings(strings, NOTIFICATION_SIGS);
    var hasFcm = MSAS.Utils.hasInStrings(strings, FCM_SIGS);

    if (hasNotification) {
      findings.push({
        ruleId: 'mastg-storage-8-notification-usage',
        ruleName: 'Local Notification APIs Detected',
        severity: 'info',
        description: 'App uses Android Notification APIs (NotificationManager, NotificationChannel). ' +
          'Notifications that display sensitive data (financial transactions, personal messages) ' +
          'on the lock screen can leak data. Use setVisibility(NotificationCompat.VISIBILITY_PRIVATE) ' +
          'to control notification visibility on secured lock screens.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: hasFcm ? 'Local + FCM notifications' : 'Local notifications'
      });
    }

    if (hasFcm) {
      var hasSensitiveFields = MSAS.Utils.hasInStrings(strings, SENSITIVE_NOTIFICATION_SIGS);
      findings.push({
        ruleId: 'mastg-storage-8-fcm-notifications',
        ruleName: 'Firebase Cloud Messaging (FCM) Notifications Detected',
        severity: hasSensitiveFields ? 'issue' : 'info',
        description: 'App uses Firebase Cloud Messaging for push notifications. ' +
          'Push notification payloads may contain sensitive data (chat messages, financial alerts). ' +
          (hasSensitiveFields ? 'Sensitive notification fields (setContentText, setTicker) detected — data may leak on lock screen. ' : '') +
          'Verify that sensitive data in notification payloads is encrypted end-to-end or ' +
          'that notification content is redacted on the lock screen using setVisibility(). ' +
          'Also ensure FCM messages are not logged or stored in SharedPreferences.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'FCM push notifications' + (hasSensitiveFields ? ' + sensitive fields' : '')
      });
    }

    if (!hasNotification && !hasFcm) {
      findings.push({
        ruleId: 'mastg-storage-8-no-notifications',
        ruleName: 'No Push Notification APIs Detected',
        severity: 'secure',
        description: 'No Android Notification or FCM push notification APIs were detected.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No notification APIs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
