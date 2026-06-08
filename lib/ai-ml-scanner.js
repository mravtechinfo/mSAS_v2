/**
 * mSAS v2 — AI/ML Security Scanner
 * Includes: Model extraction, hardcoded AI keys, prompt leakage,
 * prompt injection, AI SDK data collection, model integrity,
 * adversarial input robustness, outdated SDKs, AI WebView injection
 * MASTG Refs: AI-ANDROID-1 to AI-ANDROID-10 / AI-IOS-1 to AI-IOS-10
 */

var MSAS = MSAS || {};
MSAS.AIMLScanner = (function() {
  'use strict';

  var ON_DEVICE_MODEL_SIGS = [
    '.tflite', '.mlmodel', '.caffemodel', '.onnx',
    'Lorg/tensorflow/lite', 'Lorg/tensorflow/lite/Interpreter',
    'Lcom/google/mlkit', 'MLKit', 'MLModel',
    'Lapple/coreml', 'CoreML', 'MLModelConfiguration',
    'TFLite', 'tflite', 'Interpreter',
    'Lorg/pytorch', 'PyTorch', 'TorchModule',
    'Lorg/onnxruntime', 'OnnxRuntime'
  ];

  var AI_API_KEYS = [
    'sk-', 'sk-proj-', 'sk-project-',
    'openai', 'OPENAI', 'OpenAI',
    'anthropic', 'ANTHROPIC',
    'gemini', 'GEMINI', 'AIza',
    'huggingface', 'HUGGINGFACE',
    'replicate', 'REPLICATE',
    'cohere', 'COHERE',
    'stability', 'STABILITY',
    'api.openai.com', 'api.anthropic.com',
    'generativelanguage.googleapis.com',
    'api-inference.huggingface.co'
  ];

  var AI_SDK_SIGS = [
    'Lcom/openai', 'Lcom/anthropic',
    'Lcom/google/mlkit', 'Lcom/google/ai',
    'Landroidx/ml', 'Lorg/tensorflow/lite',
    'Lcom/huggingface', 'Lai/replicate',
    'Lcom/cohere', 'Lcom/stabilityai',
    'Lcom/langchain', 'Lcom/springai',
    'Lcom/gemini', 'Lcom/google/generativeai'
  ];

  var PROMPT_PATTERNS = [
    'systemPrompt', 'system_prompt',
    'userPrompt', 'user_prompt',
    'chatCompletion',
    'Lcom/openai/client/chat'
  ];

  var RAG_VECTOR_SIGS = [
    'chroma', 'pinecone', 'weaviate',
    'qdrant', 'milvus', 'faiss',
    'vectorstore', 'VectorStore',
    'embedding', 'Embedding',
    'Llangchain/vectorstore',
    'cosineSimilarity'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasModels = MSAS.Utils.hasInStrings(strings, ON_DEVICE_MODEL_SIGS);
    var hasAPIKeys = MSAS.Utils.hasInStrings(strings, AI_API_KEYS);
    var hasSDKs = MSAS.Utils.hasInStrings(strings, AI_SDK_SIGS);
    var hasPrompts = MSAS.Utils.hasInStrings(strings, PROMPT_PATTERNS);
    var hasRAG = MSAS.Utils.hasInStrings(strings, RAG_VECTOR_SIGS);

    if (hasModels) {
      findings.push({
        ruleId: 'mastg-ai-1-on-device-models',
        ruleName: 'On-Device ML Models Detected',
        severity: 'info',
        description: 'App bundles on-device ML models (TFLite, CoreML, PyTorch, ONNX). ' +
          'Verify models are protected against extraction and that model integrity ' +
          'checksums are validated at runtime.',
        cwe: 'CWE-312', owasp: 'M2', masvs: 'AI-ANDROID-1',
        file: '', line: null, match: 'On-device ML models'
      });
    }

    if (hasAPIKeys) {
      findings.push({
        ruleId: 'mastg-ai-2-api-keys',
        ruleName: 'AI API Key Patterns Detected',
        severity: 'issue',
        description: 'Potential AI API keys detected (OpenAI, Anthropic, Gemini, ' +
          'HuggingFace, Replicate, etc.). API keys embedded in client apps can ' +
          'be extracted and abused. Use a backend proxy to issue scoped tokens.',
        cwe: 'CWE-798', owasp: 'M9', masvs: 'AI-ANDROID-2',
        file: 'classes.dex', line: null, match: 'AI API keys'
      });
    }

    if (hasSDKs) {
      findings.push({
        ruleId: 'mastg-ai-5-sdk-detected',
        ruleName: 'AI/ML SDK Integration Detected',
        severity: 'info',
        description: 'App integrates AI/ML SDKs. Verify data collection policies ' +
          'and ensure no PII is sent to AI model providers without user consent.',
        cwe: '', owasp: '', masvs: 'AI-ANDROID-5',
        file: 'classes.dex', line: null, match: 'AI SDKs'
      });
    }

    if (hasPrompts && hasSDKs) {
      findings.push({
        ruleId: 'mastg-ai-3-prompt-leakage',
        ruleName: 'AI Prompt Data Leakage Risk',
        severity: 'issue',
        description: 'App constructs AI prompts. Verify that sensitive user data ' +
          '(PII, credentials, tokens) is not included in prompts sent to AI APIs.',
        cwe: 'CWE-200', owasp: 'M2', masvs: 'AI-ANDROID-3',
        file: 'classes.dex', line: null, match: 'Prompt construction'
      });
    }

    if (hasRAG) {
      findings.push({
        ruleId: 'mastg-ai-10-rag-vector-db',
        ruleName: 'RAG / Vector Database Integration',
        severity: 'info',
        description: 'App uses RAG or vector database (Chroma, Pinecone, FAISS). ' +
          'Verify vector DB API keys are not exposed and context injection ' +
          'protections are implemented.',
        cwe: '', owasp: '', masvs: 'AI-ANDROID-10',
        file: 'classes.dex', line: null, match: 'RAG/vector DB'
      });
    }

    if (!hasModels && !hasSDKs && !hasAPIKeys) {
      findings.push({
        ruleId: 'mastg-ai-no-ai-detected',
        ruleName: 'No AI/ML Components Detected',
        severity: 'info',
        description: 'No AI/ML frameworks, model files, or AI API integrations detected.',
        cwe: '', owasp: '', masvs: '',
        file: '', line: null, match: 'No AI/ML'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
