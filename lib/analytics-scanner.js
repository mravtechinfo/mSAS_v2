/**
 * mSAS v2 — Analytics SDK Data Leakage Scanner
 * MASTG Ref: MASTG-STORAGE-9 (Analytics Data Leakage)
 * CWE-200: Exposure of Sensitive Information
 */

var MSAS = MSAS || {};
MSAS.AnalyticsScanner = (function() {
  'use strict';

  var CWE = 'CWE-200';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-9';

  var ANALYTICS_SDKS = [
    { name: 'Firebase Analytics', sigs: ['com/google/firebase/analytics', 'FirebaseAnalytics', 'FirebaseAnalyticsEvent', 'logEvent'] },
    { name: 'Google Analytics', sigs: ['com/google/android/gms/analytics', 'GoogleAnalytics', 'Tracker', 'GAServiceManager'] },
    { name: 'Mixpanel', sigs: ['com/mixpanel/android', 'MixpanelAPI', 'mixpanel'] },
    { name: 'Amplitude', sigs: ['com/amplitude/api', 'AmplitudeClient', 'Amplitude'] },
    { name: 'Segment', sigs: ['com/segment/analytics', 'Analytics', 'Segment'] },
    { name: 'Facebook Analytics', sigs: ['com/facebook/appevents', 'AppEventsLogger'] },
    { name: 'AppsFlyer', sigs: ['com/appsflyer', 'AppsFlyerLib', 'AppsFlyerConversionListener'] },
    { name: 'Adjust', sigs: ['com/adjust/sdk', 'Adjust', 'AdjustEvent'] },
    { name: 'Flurry', sigs: ['com/flurry/android', 'FlurryAgent', 'Flurry'] },
    { name: 'Braze (Appboy)', sigs: ['com/appboy', 'Braze', 'Appboy'] },
    { name: 'CleverTap', sigs: ['com/clevertap/android', 'CleverTapAPI'] },
    { name: 'Leanplum', sigs: ['com/leanplum', 'Leanplum'] },
    { name: 'Localytics', sigs: ['com/localytics/android', 'Localytics'] },
    { name: 'Countly', sigs: ['ly/count/android', 'Countly'] },
    { name: 'UXCam', sigs: ['com/uxcam', 'UXCam'] },
    { name: 'Hotjar', sigs: ['com/hotjar', 'Hotjar'] },
    { name: 'Matomo (Piwik)', sigs: ['org/matomo/sdk', 'Matomo', 'Piwik'] }
  ];

  var PII_FIELD_SIGS = [
    'userEmail', 'user_email', 'userEmailAddress',
    'userName', 'username', 'user_name',
    'userPhone', 'phoneNumber', 'phone_number',
    'userID', 'userId', 'user_id',
    'deviceId', 'device_id', 'deviceID',
    'advertisingId', 'advertising_id', 'adId',
    'userProperty', 'user_property',
    'setUserEmail', 'setUserName', 'setUserPhone',
    'setUserId', 'identify'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var detectedSDKs = [];
    for (var i = 0; i < ANALYTICS_SDKS.length; i++) {
      if (MSAS.Utils.hasInStrings(strings, ANALYTICS_SDKS[i].sigs)) {
        detectedSDKs.push(ANALYTICS_SDKS[i].name);
      }
    }

    var hasPIIFields = MSAS.Utils.hasInStrings(strings, PII_FIELD_SIGS);

    if (detectedSDKs.length > 0) {
      findings.push({
        ruleId: 'mastg-storage-9-analytics-sdk',
        ruleName: 'Analytics / Telemetry SDK Detected',
        severity: hasPIIFields ? 'issue' : 'info',
        description: 'The app integrates ' + detectedSDKs.length + ' analytics SDK' +
          (detectedSDKs.length > 1 ? 's' : '') + ': ' + detectedSDKs.join(', ') + '. ' +
          (hasPIIFields
            ? '⚠️ PII-related field names detected in DEX strings. Analytics data may include ' +
              'identifiable user information (email, name, phone, device IDs). Verify that ' +
              'analytics events do not transmit PII and that user consent is obtained.'
            : 'Verify that analytics configuration excludes PII transmission and complies ' +
              'with privacy regulations (GDPR, CCPA, etc).'),
        cwe: hasPIIFields ? CWE : '',
        owasp: hasPIIFields ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: detectedSDKs.join(', ') + (hasPIIFields ? ' + possible PII fields' : '')
      });
    } else {
      findings.push({
        ruleId: 'mastg-storage-9-no-analytics',
        ruleName: 'No Analytics SDK Detected',
        severity: 'secure',
        description: 'No major analytics or telemetry SDKs were detected in the app. ' +
          'If analytics is implemented via custom code, manually verify PII handling.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No analytics SDKs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
