/**
 * mSAS v2 — Deserialization Vulnerability Scanner
 * MASTG Ref: MASTG-CODE-7 (Deserialization)
 * CWE-502: Deserialization of Untrusted Data
 */

var MSAS = MSAS || {};
MSAS.DeserializationScanner = (function() {
  'use strict';

  var CWE = 'CWE-502';
  var OWASP = 'M7';
  var MASVS = 'CODE-7';

  var JAVA_DESER_SIGS = [
    'Ljava/io/ObjectInputStream',
    'Ljava/io/ObjectOutputStream',
    'ObjectInputStream',
    'readObject',
    'readUnshared',
    'writeObject',
    'writeUnshared',
    'Ljava/io/Externalizable',
    'readExternal',
    'writeExternal'
  ];

  var JSON_DESER_SIGS = [
    'Lcom/google/gson/Gson',
    'Lcom/fasterxml/jackson/databind/ObjectMapper',
    'Lorg/json/JSONTokener',
    'Gson',
    'ObjectMapper',
    'fromJson',
    'readValue',
    'JSONTokener'
  ];

  var JACKSON_DANGER_SIGS = [
    'enableDefaultTyping',
    'activateDefaultTyping',
    'Lcom/fasterxml/jackson/databind/ObjectMapper;->enableDefaultTyping',
    'DefaultTyping'
  ];

  var XML_DESER_SIGS = [
    'Ljavax/xml/parsers/DocumentBuilder',
    'Lorg/xml/sax/SAXParser',
    'SAXParser',
    'DocumentBuilder',
    'Ljavax/xml/parsers/SAXParser',
    'Lorg/xmlpull/v1/XmlPullParser'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasJavaDeser = MSAS.Utils.hasInStrings(strings, JAVA_DESER_SIGS);
    var hasJsonDeser = MSAS.Utils.hasInStrings(strings, JSON_DESER_SIGS);
    var hasJacksonDanger = MSAS.Utils.hasInStrings(strings, JACKSON_DANGER_SIGS);
    var hasXmlDeser = MSAS.Utils.hasInStrings(strings, XML_DESER_SIGS);

    if (hasJavaDeser) {
      findings.push({
        ruleId: 'mastg-code-7-deserialization',
        ruleName: hasJacksonDanger
          ? '⚠️ Insecure Deserialization (Jackson Default Typing)'
          : 'Java Object Deserialization Detected',
        severity: hasJacksonDanger ? 'issue' : 'info',
        description: 'App uses Java serialization/deserialization.' +
          (hasJacksonDanger
            ? ' ⚠️ Jackson ObjectMapper with enabled default typing allows ' +
              'arbitrary class instantiation from JSON, enabling remote code ' +
              'execution through gadget chains. Disable default typing and use ' +
              'whitelisted @JsonTypeInfo annotations instead.'
            : ' Verify that deserialization is not performed on untrusted data. ' +
              'ObjectInputStream.readObject() on attacker-controlled data can ' +
              'lead to remote code execution via gadget chains.'),
        cwe: hasJacksonDanger ? CWE : '',
        owasp: hasJacksonDanger ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: hasJacksonDanger ? 'Jackson default typing' : 'Java serialization'
      });
    }

    if (!hasJavaDeser && !hasJsonDeser && !hasXmlDeser) {
      findings.push({
        ruleId: 'mastg-code-7-no-deser',
        ruleName: 'No Deserialization APIs Detected',
        severity: 'secure',
        description: 'No Java deserialization, JSON parsing, or XML parsing ' +
          'APIs detected.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No deserialization'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
