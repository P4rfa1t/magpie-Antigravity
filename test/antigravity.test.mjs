import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { GeminiWebPlugin, AntigravityPlugin } from '../index.mjs';
import {
  GCP_OAUTH_CLIENT,
  PERSONAL_OAUTH_CLIENT,
  loadAntigravityAccounts,
  parseRefreshTokenInput,
  refreshAccessToken,
  removeAntigravityAccount,
  saveAntigravityAccount,
  verifyRefreshToken
} from '../lib/antigravity-oauth.mjs';
import {
  SENTINEL_SIGNATURE,
  antigravitySSEToOpenAIStream,
  antigravityToOpenAIResponse,
  cleanJsonSchema,
  openAIToAntigravityRequest,
  resolveAntigravityModel
} from '../lib/antigravity-mapper.mjs';
import {
  ANTIGRAVITY_BASE,
  ANTIGRAVITY_ID,
  antigravitySettings,
  buildAntigravityModels
} from '../lib/antigravity.mjs';

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'magpie-antigravity-test-'));
}

const SAMPLE_CATALOG = {
  models: {
    'gemini-4-hydrogen-low': {
      displayName: 'Gemini 4 Hydrogen (Low)',
      modelProvider: 'MODEL_PROVIDER_GOOGLE',
      thinkingLevel: 1,
      maxOutputTokens: 262144
    },
    'gemini-4-hydrogen-medium': {
      displayName: 'Gemini 4 Hydrogen (Medium)',
      modelProvider: 'MODEL_PROVIDER_GOOGLE',
      thinkingLevel: 2,
      maxOutputTokens: 262144
    },
    'gemini-4-hydrogen-high': {
      displayName: 'Gemini 4 Hydrogen (High)',
      modelProvider: 'MODEL_PROVIDER_GOOGLE',
      thinkingLevel: 3,
      maxOutputTokens: 262144
    },
    'gemini-4-hydrogen-xhigh': {
      displayName: 'Gemini 4 Hydrogen (XHigh)',
      modelProvider: 'MODEL_PROVIDER_GOOGLE',
      thinkingLevel: 100,
      maxOutputTokens: 262144
    },
    'gemini-4-hydrogen-tiered-xhigh': {
      displayName: 'Gemini 4 Hydrogen (XHigh)',
      modelProvider: 'MODEL_PROVIDER_GOOGLE',
      thinkingLevel: 100,
      maxOutputTokens: 262144
    },
    'claude-opus-5-5-low': {
      displayName: 'Claude Opus 5.5 (Low)',
      modelProvider: 'MODEL_PROVIDER_ANTHROPIC',
      thinkingLevel: 1,
      maxOutputTokens: 128000
    },
    'claude-opus-5-5-high': {
      displayName: 'Claude Opus 5.5 (High)',
      modelProvider: 'MODEL_PROVIDER_ANTHROPIC',
      thinkingLevel: 3,
      maxOutputTokens: 128000
    },
    'gpt-oss-120b-medium': {
      displayName: 'GPT-OSS 120B (Medium)',
      modelProvider: 'MODEL_PROVIDER_OPENAI',
      thinkingBudget: 8192,
      maxOutputTokens: 32768
    },
    'gemini-3.1-flash-image': {
      displayName: 'Gemini 3.1 Flash Image',
      modelProvider: 'MODEL_PROVIDER_GOOGLE',
      maxOutputTokens: 65536
    },
    'gemini-4-carbon-disabled': {
      displayName: 'Gemini 4 Carbon',
      modelProvider: 'MODEL_PROVIDER_GOOGLE',
      disabled: true
    },
    'tab_flash_lite_preview': {
      modelProvider: 'MODEL_PROVIDER_GOOGLE'
    },
    'gemini-2.5-pro': {
      displayName: 'Gemini 2.5 Pro',
      modelProvider: 'MODEL_PROVIDER_GOOGLE'
    }
  },
  imageGenerationModelIds: ['gemini-3.1-flash-image']
};

describe('Antigravity Refresh Token parser', () => {
  it('parses single token, JSON array, and arbitrary text with deduplication', () => {
    assert.deepEqual(parseRefreshTokenInput('  1//03abc_DEF-123  '), ['1//03abc_DEF-123']);

    const jsonArr = JSON.stringify([
      { email: 'a@gmail.com', refresh_token: '1//03tokenA' },
      { email: 'b@gmail.com', token: { refresh_token: '1//03tokenB' } },
      { email: 'dup@gmail.com', refresh_token: '1//03tokenA' }
    ]);
    assert.deepEqual(parseRefreshTokenInput(jsonArr), ['1//03tokenA', '1//03tokenB']);

    const noisy = 'account1: 1//03first_tok\naccount2: 1//03second-tok and again 1//03first_tok';
    assert.deepEqual(parseRefreshTokenInput(noisy), ['1//03first_tok', '1//03second-tok']);
  });

  it('rejects empty or invalid inputs', () => {
    assert.throws(() => parseRefreshTokenInput(''), /没有收到 Refresh Token/);
    assert.throws(() => parseRefreshTokenInput('not-a-token'), /未识别到有效的 Refresh Token/);
  });
});

describe('Antigravity OAuth refresh & account storage', () => {
  it('falls back to GCP client on client mismatch and retries invalid_grant once', async () => {
    const calls = [];
    const fetchFn = async (_url, init) => {
      const body = new URLSearchParams(init.body);
      calls.push(body.get('client_id'));
      if (body.get('client_id') === 'test-personal-id') {
        return Response.json({ error: 'unauthorized_client' }, { status: 401 });
      }
      return Response.json({ access_token: 'ya29.gcp', expires_in: 3600 });
    };

    const res = await refreshAccessToken('1//03test', {
      clientType: 'personal',
      clientId: 'test-personal-id',
      clientSecret: 'test-personal-secret',
      gcpClientId: 'test-gcp-id',
      gcpClientSecret: 'test-gcp-secret',
      retryDelayMs: 0,
      fetchFn
    });
    assert.equal(res.accessToken, 'ya29.gcp');
    assert.equal(res.oauthClientKey, GCP_OAUTH_CLIENT.key);
    assert.equal(res.clientType, 'enterprise');
    assert.deepEqual(calls, ['test-personal-id', 'test-gcp-id']);
  });

  it('flags invalidGrant after retry', async () => {
    let attempts = 0;
    const fetchFn = async () => {
      attempts++;
      return Response.json({ error: 'invalid_grant' }, { status: 400 });
    };
    await assert.rejects(
      refreshAccessToken('1//03revoked', {
        clientId: 'test-personal-id',
        clientSecret: 'test-personal-secret',
        gcpClientId: 'test-gcp-id',
        gcpClientSecret: 'test-gcp-secret',
        retryDelayMs: 0,
        fetchFn
      }),
      err => err.invalidGrant === true && err.signIn === 'expired'
    );
    assert.equal(attempts, 4); // 2 clients x 2 attempts each
  });

  it('verifies token and persists accounts cleanly', async () => {
    const dir = makeTempDir();
    const fetchFn = async url => {
      if (url.includes('oauth2.googleapis.com/token')) {
        return Response.json({ access_token: 'ya29.ok', expires_in: 3600 });
      }
      if (url.includes('/userinfo')) {
        return Response.json({ email: 'Tester@Gmail.com', name: 'Test User' });
      }
      if (url.includes(':loadCodeAssist')) {
        return Response.json({
          cloudaicompanionProject: 'aicode-consumers',
          paidTier: { id: 'g1-pro-tier' }
        });
      }
      if (url.includes(':fetchAvailableModels')) {
        return Response.json(SAMPLE_CATALOG);
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const verified = await verifyRefreshToken('1//03good', {
      clientId: 'test-personal-id',
      clientSecret: 'test-personal-secret',
      dataDir: dir,
      fetchFn
    });
    assert.equal(verified.email, 'Tester@Gmail.com');
    assert.equal(verified.tier, 'PRO');
    assert.equal(verified.projectId, 'aicode-consumers');
    assert.equal(verified.modelsCount, Object.keys(SAMPLE_CATALOG.models).length);

    saveAntigravityAccount(verified, dir);
    const loaded = loadAntigravityAccounts(dir);
    assert.equal(loaded.length, 1);
    assert.equal(loaded[0].refreshToken, '1//03good');

    assert.equal(removeAntigravityAccount('tester@gmail.com', dir), true);
    assert.equal(loadAntigravityAccounts(dir).length, 0);
  });
});

describe('Antigravity model catalog & schema cleaning', () => {
  it('collapses tier variants, hides disabled/internal/legacy models, and configures image models', () => {
    const models = buildAntigravityModels(SAMPLE_CATALOG, antigravitySettings());
    assert.ok(models['gemini-4-hydrogen']);
    assert.deepEqual(Object.keys(models['gemini-4-hydrogen'].variants), ['low', 'medium', 'high', 'xhigh']);
    assert.equal(models['gemini-4-hydrogen'].name, 'Gemini 4 Hydrogen');
    assert.equal(models['gemini-4-hydrogen'].limit.output, 262144);
    assert.equal(models['gemini-4-hydrogen'].capabilities.toolcall, true);

    assert.ok(models['claude-opus-5-5']);
    assert.deepEqual(Object.keys(models['claude-opus-5-5'].variants), ['low', 'high']);
    assert.equal(models['claude-opus-5-5'].limit.context, 200000);

    assert.ok(models['gpt-oss-120b-medium']);
    assert.equal(models['gemini-3.1-flash-image'].api.npm, '@ai-sdk/google');
    assert.equal(models['gemini-3.1-flash-image'].capabilities.output.image, true);

    assert.equal(models['gemini-4-carbon-disabled'], undefined);
    assert.equal(models['tab_flash_lite_preview'], undefined);
    assert.equal(models['gemini-2.5-pro'], undefined);
    assert.equal(models['gemini-4-hydrogen-tiered-xhigh'], undefined);

    const noImages = buildAntigravityModels(SAMPLE_CATALOG, antigravitySettings({ antigravity: { imageModels: false } }));
    assert.equal(noImages['gemini-3.1-flash-image'], undefined);
  });

  it('cleans JSON schemas ($ref, anyOf null union, const, required alignment, uppercase types)', () => {
    const cleaned = cleanJsonSchema({
      $schema: 'http://json-schema.org/draft-07/schema#',
      $defs: {
        Unit: { type: 'string', enum: ['c', 'f'] }
      },
      type: 'object',
      additionalProperties: false,
      properties: {
        city: { anyOf: [{ type: 'string' }, { type: 'null' }], description: 'City name' },
        unit: { $ref: '#/$defs/Unit' },
        mode: { const: 'fast' }
      },
      required: ['city', 'missing_key']
    });

    assert.equal(cleaned.type, 'OBJECT');
    assert.equal(cleaned.$schema, undefined);
    assert.equal(cleaned.additionalProperties, undefined);
    assert.equal(cleaned.properties.city.type, 'STRING');
    assert.deepEqual(cleaned.properties.unit, { type: 'STRING', enum: ['c', 'f'] });
    assert.deepEqual(cleaned.properties.mode, { type: 'STRING', enum: ['fast'] });
    assert.deepEqual(cleaned.required, ['city']);
  });
});

describe('Antigravity OpenAI <-> v1internal mapping', () => {
  it('maps system messages, tools, thoughtSignature fallback, and reasoning effort', () => {
    const cache = new Map([['call_prev', 'real_sig_abc']]);
    const { targetModel, envelope } = openAIToAntigravityRequest({
      model: 'gemini-4-hydrogen',
      reasoning_effort: 'xhigh',
      messages: [
        { role: 'system', content: 'Be concise.' },
        {
          role: 'user',
          content: [
            { type: 'text', text: 'Check weather' },
            { type: 'image_url', image_url: { url: 'data:image/png;base64,AAAA' } }
          ]
        },
        {
          role: 'assistant',
          reasoning_content: 'Need weather tool.',
          tool_calls: [
            { id: 'call_prev', type: 'function', function: { name: 'get_weather', arguments: '{"city":"Tokyo"}' } },
            { id: 'call_new', type: 'function', function: { name: 'get_time', arguments: '{"tz":"JST"}' } }
          ]
        },
        { role: 'tool', tool_call_id: 'call_prev', content: '22C' },
        { role: 'tool', tool_call_id: 'call_new', content: '12:00' }
      ],
      tools: [{
        type: 'function',
        function: {
          name: 'get_weather',
          description: 'Weather lookup',
          parameters: { type: 'object', properties: { city: { type: 'string' } }, required: ['city'] }
        }
      }]
    }, {
      catalog: SAMPLE_CATALOG,
      projectId: 'aicode-consumers',
      email: 'user@gmail.com',
      signatureCache: cache,
      sessionId: 'sess-1'
    });

    assert.equal(targetModel, 'gemini-4-hydrogen-xhigh');
    assert.equal(resolveAntigravityModel('gemini-4-hydrogen', 'low', SAMPLE_CATALOG), 'gemini-4-hydrogen-low');
    assert.equal(envelope.requestType, 'agent');
    assert.equal(envelope.userAgent, 'antigravity');
    assert.deepEqual(envelope.request.systemInstruction, { role: 'user', parts: [{ text: 'Be concise.' }] });
    assert.deepEqual(envelope.request.generationConfig.thinkingConfig, { includeThoughts: true, thinkingLevel: 100 });
    assert.equal(envelope.request.contents[0].parts[1].inlineData.data, 'AAAA');
    assert.equal(envelope.request.contents[1].parts[0].thought, true);
    assert.equal(envelope.request.contents[1].parts[1].thoughtSignature, 'real_sig_abc');
    assert.equal(envelope.request.contents[1].parts[2].thoughtSignature, SENTINEL_SIGNATURE);
    // Consecutive tool responses grouped into one user turn.
    assert.equal(envelope.request.contents[2].role, 'user');
    assert.equal(envelope.request.contents[2].parts.length, 2);
    assert.equal(envelope.request.contents[2].parts[0].functionResponse.name, 'get_weather');
    assert.equal(envelope.request.contents[2].parts[1].functionResponse.name, 'get_time');
  });

  it('converts non-streaming and streaming v1internal responses to OpenAI format', async () => {
    const cache = new Map();
    const openAIResp = antigravityToOpenAIResponse({
      response: {
        responseId: 'resp-1',
        candidates: [{
          content: {
            parts: [
              { text: 'Thinking...', thought: true },
              { thoughtSignature: 'sig-xyz', functionCall: { name: 'ping', args: { host: '1.1.1.1' }, id: 'c1' } }
            ]
          },
          finishReason: 'STOP'
        }],
        usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 5, thoughtsTokenCount: 3, totalTokenCount: 18 }
      }
    }, { model: 'gemini-4-hydrogen', signatureCache: cache });

    assert.equal(openAIResp.choices[0].message.reasoning_content, 'Thinking...');
    assert.equal(openAIResp.choices[0].message.tool_calls[0].function.name, 'ping');
    assert.equal(openAIResp.choices[0].finish_reason, 'tool_calls');
    assert.equal(openAIResp.usage.completion_tokens, 8);
    assert.equal(cache.get('c1'), 'sig-xyz');

    const ssePayload = [
      'data: {"response":{"candidates":[{"content":{"parts":[{"text":"Plan","thought":true}]}}]}}\n\n',
      'data: {"response":{"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":5,"candidatesTokenCount":2,"thoughtsTokenCount":1,"totalTokenCount":8}}}\n\n'
    ].join('');
    const upstreamStream = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(ssePayload));
        c.close();
      }
    });
    const outStream = antigravitySSEToOpenAIStream(upstreamStream, {
      model: 'gemini-4-hydrogen',
      includeUsage: true
    });
    const outText = await new Response(outStream).text();
    assert.match(outText, /"reasoning_content":"Plan"/);
    assert.match(outText, /"content":"Hello"/);
    assert.match(outText, /"finish_reason":"stop"/);
    assert.match(outText, /"reasoning_tokens":1/);
    assert.match(outText, /data: \[DONE\]\n\n$/);
  });
});

describe('AntigravityPlugin integration with Magpie contract', () => {
  it('coexists with GeminiWebPlugin when antigravity options are passed', async () => {
    const web = await GeminiWebPlugin({}, { antigravity: { proxy: 'http://127.0.0.1:7890' } });
    assert.equal(web.auth.provider, 'gemini-web');
  });

  it('signs in via Refresh Token, lists models, reads quota, and rotates accounts on 429', async () => {
    const dir = makeTempDir();
    const requestLog = [];
    const fetchFn = async (url, init) => {
      requestLog.push({ url, headers: init?.headers, body: init?.body });
      if (url.includes('oauth2.googleapis.com/token')) {
        const params = new URLSearchParams(init.body);
        const rt = params.get('refresh_token');
        return Response.json({ access_token: rt === '1//03acc1' ? 'tok1' : 'tok2', expires_in: 3600 });
      }
      if (url.includes('/userinfo')) {
        const authHdr = init.headers.Authorization;
        return Response.json({ email: authHdr === 'Bearer tok1' ? 'one@gmail.com' : 'two@gmail.com' });
      }
      if (url.includes(':loadCodeAssist')) {
        return Response.json({ cloudaicompanionProject: 'aicode-consumers', paidTier: { id: 'g1-pro-tier' } });
      }
      if (url.includes(':fetchAvailableModels')) {
        return Response.json(SAMPLE_CATALOG);
      }
      if (url.includes(':retrieveUserQuotaSummary')) {
        return Response.json({
          groups: [
            {
              displayName: 'Gemini Models',
              buckets: [
                { window: '5h', remainingFraction: 0.9, resetTime: '2026-11-22T20:00:00Z' },
                { window: 'weekly', remainingFraction: 0.8, resetTime: '2026-11-29T20:00:00Z' }
              ]
            },
            {
              displayName: 'Claude and GPT models',
              buckets: [
                { window: '5h', remainingFraction: 0, resetTime: '2026-11-22T20:30:00Z' }
              ]
            }
          ]
        });
      }
      if (url.includes(':generateContent')) {
        if (init.headers.Authorization === 'Bearer tok1') {
          return Response.json({ error: { code: 429, message: 'RESOURCE_EXHAUSTED' } }, { status: 429 });
        }
        return Response.json({
          response: {
            candidates: [{ content: { parts: [{ text: 'from-account-2' }] }, finishReason: 'STOP' }],
            usageMetadata: { promptTokenCount: 4, candidatesTokenCount: 3, totalTokenCount: 7 }
          }
        });
      }
      throw new Error(`Unexpected URL: ${url}`);
    };

    const plugin = await AntigravityPlugin({}, {
      antigravity: {
        dataDir: dir,
        clientId: 'test-personal-id',
        clientSecret: 'test-personal-secret'
      },
      fetchFn
    });
    const cfg = {};
    await plugin.config(cfg);
    assert.equal(cfg.provider[ANTIGRAVITY_ID].name, 'Antigravity (RT)');
    assert.equal(ANTIGRAVITY_ID, 'antigravity-rt');

    const flow = await plugin.auth.methods[0].authorize({ clientType: 'personal', proxy: '' });
    assert.equal(flow.method, 'code');
    const signIn = await flow.callback(JSON.stringify([
      { refresh_token: '1//03acc1' },
      { refresh_token: '1//03acc2' }
    ]));
    assert.equal(signIn.type, 'success');
    assert.equal(signIn.metadata.accounts.length, 2);

    const authObj = { type: 'api', key: signIn.key, metadata: signIn.metadata };
    const models = await plugin.provider.models({ models: {} }, { auth: authObj });
    assert.ok(models['gemini-4-hydrogen']);

    const usageCard = await plugin.auth.usage(async () => authObj);
    assert.equal(usageCard.plan, 'PRO');
    assert.equal(usageCard.windows.length, 3);
    assert.equal(usageCard.windows[0].name, 'Gemini 5h');
    assert.equal(usageCard.windows[0].used, 10);
    assert.equal(usageCard.windows[2].name, 'Claude/GPT 5h');
    assert.equal(usageCard.windows[2].used, 100);

    const loader = await plugin.auth.loader(async () => authObj);
    assert.equal(loader.baseURL, ANTIGRAVITY_BASE);
    const chatRes = await loader.fetch(`${ANTIGRAVITY_BASE}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-opus-5-5',
        reasoning_effort: 'high',
        messages: [{ role: 'user', content: 'hi' }],
        stream: false
      })
    });
    assert.equal(chatRes.status, 200);
    const chatJson = await chatRes.json();
    assert.equal(chatJson.choices[0].message.content, 'from-account-2');

    const genCall = requestLog.find(r => r.url.includes(':generateContent') && r.headers.Authorization === 'Bearer tok2');
    assert.equal(genCall.headers['anthropic-beta'], 'claude-code-20250219');
    assert.equal(genCall.headers['x-goog-user-project'], undefined); // consumer aicode-consumers stripped
  });

  it('prompts for OAuth client_id/client_secret when unconfigured and persists embedded JSON credentials', async () => {
    const dir = makeTempDir();
    const fetchFn = async url => {
      if (url.includes('oauth2.googleapis.com/token')) return Response.json({ access_token: 'tok', expires_in: 3600 });
      if (url.includes('/userinfo')) return Response.json({ email: 'prompt@gmail.com' });
      if (url.includes(':loadCodeAssist')) return Response.json({ cloudaicompanionProject: 'aicode-consumers' });
      if (url.includes(':fetchAvailableModels')) return Response.json(SAMPLE_CATALOG);
      throw new Error(`Unexpected URL: ${url}`);
    };
    const plugin = await AntigravityPlugin({}, { antigravity: { dataDir: dir }, fetchFn });
    const method = plugin.auth.methods[0];
    assert.equal((await method.ask({ clientType: 'personal', proxy: '' })).key, 'clientId');
    assert.equal((await method.ask({ clientType: 'personal', proxy: '', clientId: 'cid' })).key, 'clientSecret');
    assert.equal(await method.ask({ clientType: 'personal', proxy: '', clientId: '' }), null);

    const flow = await method.authorize({ clientType: 'personal', proxy: '' });
    const res = await flow.callback(JSON.stringify({
      refresh_token: '1//03embedded',
      client_id: 'embedded-id',
      client_secret: 'embedded-secret'
    }));
    assert.equal(res.type, 'success');
    // Subsequent login skips clientId prompt because oauth-clients.json was saved.
    assert.equal(await method.ask({ clientType: 'personal', proxy: '' }), null);
  });
});
