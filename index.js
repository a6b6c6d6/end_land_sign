const axios = require('axios');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const NodeRSA = require('node-rsa');
const { v4: uuidv4 } = require('uuid');
const zlib = require('zlib');
const moment = require('moment');

// 常量定义
const RSA_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB";

const DES_RULE = {
  "appId": { "cipher": "DES", "is_encrypt": 1, "key": "uy7mzc4h", "obfuscated_name": "xx" },
  "box": { "is_encrypt": 0, "obfuscated_name": "jf" },
  "canvas": { "cipher": "DES", "is_encrypt": 1, "key": "snrn887t", "obfuscated_name": "yk" },
  "clientSize": { "cipher": "DES", "is_encrypt": 1, "key": "cpmjjgsu", "obfuscated_name": "zx" },
  "organization": { "cipher": "DES", "is_encrypt": 1, "key": "78moqjfc", "obfuscated_name": "dp" },
  "os": { "cipher": "DES", "is_encrypt": 1, "key": "je6vk6t4", "obfuscated_name": "pj" },
  "platform": { "cipher": "DES", "is_encrypt": 1, "key": "pakxhcd2", "obfuscated_name": "gm" },
  "plugins": { "cipher": "DES", "is_encrypt": 1, "key": "v51m3pzl", "obfuscated_name": "kq" },
  "pmf": { "cipher": "DES", "is_encrypt": 1, "key": "2mdeslu3", "obfuscated_name": "vw" },
  "protocol": { "is_encrypt": 0, "obfuscated_name": "protocol" },
  "referer": { "cipher": "DES", "is_encrypt": 1, "key": "y7bmrjlc", "obfuscated_name": "ab" },
  "res": { "cipher": "DES", "is_encrypt": 1, "key": "whxqm2a7", "obfuscated_name": "hf" },
  "rtype": { "cipher": "DES", "is_encrypt": 1, "key": "x8o2h2bl", "obfuscated_name": "lo" },
  "sdkver": { "cipher": "DES", "is_encrypt": 1, "key": "9q3dcxp2", "obfuscated_name": "sc" },
  "status": { "cipher": "DES", "is_encrypt": 1, "key": "2jbrxxw4", "obfuscated_name": "an" },
  "subVersion": { "cipher": "DES", "is_encrypt": 1, "key": "eo3i2puh", "obfuscated_name": "ns" },
  "svm": { "cipher": "DES", "is_encrypt": 1, "key": "fzj3kaeh", "obfuscated_name": "qr" },
  "time": { "cipher": "DES", "is_encrypt": 1, "key": "q2t3odsk", "obfuscated_name": "nb" },
  "timezone": { "cipher": "DES", "is_encrypt": 1, "key": "1uv05lj5", "obfuscated_name": "as" },
  "tn": { "cipher": "DES", "is_encrypt": 1, "key": "x9nzj1bp", "obfuscated_name": "py" },
  "trees": { "cipher": "DES", "is_encrypt": 1, "key": "acfs0xo4", "obfuscated_name": "pi" },
  "ua": { "cipher": "DES", "is_encrypt": 1, "key": "k92crp1t", "obfuscated_name": "bj" },
  "url": { "cipher": "DES", "is_encrypt": 1, "key": "y95hjkoo", "obfuscated_name": "cf" },
  "version": { "is_encrypt": 0, "obfuscated_name": "version" },
  "vpw": { "cipher": "DES", "is_encrypt": 1, "key": "r9924ab5", "obfuscated_name": "ca" },
};

const DES_TARGET_BASE = {
  "protocol": "102",
  "organization": "UWXspnCCJN4sfYlNfqps",
  "appId": "default",
  "os": "web",
  "version": "3.0.0",
  "sdkver": "3.0.0",
  "box": "",
  "rtype": "all",
  "subVersion": "1.0.0",
};

const BROWSER_ENV = {
  "plugins": "MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1",
  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
  "canvas": "259ffe69",
  "timezone": "-480",
  "platform": "Win32",
  "url": "https://www.skland.com/",
  "referer": "",
  "res": "1920_1080_24_1.25",
  "clientSize": "0_0_1080_1920_1920_1080_1920_1080",
};

const USER_AGENT = "Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1";

// DES 加密 (ECB 模式, NULL 填充)
function desEncrypt(key, data) {
  // 使用 crypto-js 的 DES
  const keyHex = CryptoJS.enc.Utf8.parse(key);
  const dataHex = CryptoJS.enc.Utf8.parse(data);
  
  // ECB 模式
  const encrypted = CryptoJS.DES.encrypt(dataHex, keyHex, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.ZeroPadding
  });
  
  return Buffer.from(encrypted.ciphertext.toString(CryptoJS.enc.Base64), 'base64');
}

// AES-128-CBC 加密
function aesEncrypt(data, key) {
  // Base64 编码
  const base64Data = Buffer.from(data).toString('base64');
  
  // 密钥处理 (16字节)
  const keyBuffer = Buffer.alloc(16);
  Buffer.from(key).copy(keyBuffer);
  
  const iv = Buffer.from("0102030405060708");
  
  const cipher = crypto.createCipheriv('aes-128-cbc', keyBuffer, iv);
  let encrypted = cipher.update(base64Data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted.toUpperCase();
}

// 生成 SMID
function getSmid() {
  const timeStr = moment().format('YYYYMMDDHHmmss');
  const uid = uuidv4();
  const uidHash = crypto.createHash('md5').update(uid).digest('hex');
  const v = `${timeStr}${uidHash}00`;
  const smskWeb = crypto.createHash('md5').update(`smsk_web_${v}`).digest();
  const suffix = smskWeb.slice(0, 7).toString('hex');
  return `${v}${suffix}0`;
}

// 生成 TN
function getTn(data) {
  const sortedKeys = Object.keys(data).sort();
  let result = "";
  for (const key of sortedKeys) {
    const value = data[key];
    if (!isNaN(parseInt(value)) && !isNaN(value)) {
      result += (parseInt(value) * 10000).toString();
    } else {
      result += value;
    }
  }
  return result;
}

// 应用 DES 规则
function applyDesRules(data) {
  const result = {};
  for (const [key, value] of Object.entries(data)) {
    const rule = DES_RULE[key];
    if (rule) {
      if (rule.is_encrypt === 1) {
        const encrypted = desEncrypt(rule.key, value.toString());
        result[rule.obfuscated_name] = encrypted.toString('base64');
      } else {
        result[rule.obfuscated_name] = value;
      }
    } else {
      result[key] = value;
    }
  }
  return result;
}

class SklandClient {
  constructor() {
    this.deviceId = process.env.SKLAND_DEVICE_ID || "";
    this.userAgent = USER_AGENT;
    this.maxRetries = 3;
  }

  async getDeviceId() {
    if (this.deviceId) return this.deviceId;
    
    // 生成设备 ID
    const uid = uuidv4();
    const uidHash = crypto.createHash('md5').update(uid).digest();
    const priIdHex = uidHash.slice(0, 8).toString('hex');

    // RSA 加密
    const key = new NodeRSA();
    key.importKey(Buffer.from(RSA_PUBLIC_KEY, 'base64'), 'pkcs1-public-der');
    key.setOptions({ encryptionScheme: 'pkcs1' });
    const encryptedUid = key.encrypt(Buffer.from(uid), 'base64');
    
    const epBase64 = encryptedUid;

    // 构建指纹
    const inMs = Date.now();
    const desTarget = {
      ...DES_TARGET_BASE,
      ...BROWSER_ENV,
      smid: getSmid(),
      vpw: uuidv4(),
      trees: uuidv4(),
      svm: inMs.toString(),
      pmf: inMs.toString(),
      time: inMs.toString()
    };

    // 计算 TN
    const tnInput = getTn(desTarget);
    const tn = crypto.createHash('md5').update(tnInput).digest('hex');
    desTarget.tn = tn;

    // DES 处理
    const desResult = applyDesRules(desTarget);
    
    // JSON + Gzip
    const jsonStr = JSON.stringify(desResult);
    const compressed = zlib.gzipSync(jsonStr, { level: 2 });
    
    // AES 加密
    const encrypted = aesEncrypt(compressed, priIdHex);

    // 请求设备 ID
    try {
      const resp = await axios.post('https://fp-it.portal101.cn/deviceprofile/v4', {
        appId: "default",
        compress: 2,
        data: encrypted,
        encode: 5,
        ep: epBase64,
        organization: "UWXspnCCJN4sfYlNfqps",
        os: "web"
      }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 30000
      });

      if (resp.data.code !== 1100) {
        throw new Error(`Device ID generation failed: ${JSON.stringify(resp.data)}`);
      }

      this.deviceId = `B${resp.data.detail.deviceId}`;
      return this.deviceId;
    } catch (e) {
      console.error('Device ID generation error:', e.message);
      throw e;
    }
  }

  generateSignature(token, path, body, did) {
    const timestamp = Math.floor(Date.now() / 1000);
    const commonArgs = {
      platform: "3",
      timestamp: timestamp.toString(),
      dId: did,
      vName: "1.0.0"
    };

    const signStr = `${path}${body || ""}${timestamp}${JSON.stringify(commonArgs)}`;
    
    // HMAC-SHA256
    const hmac = crypto.createHmac('sha256', token);
    hmac.update(signStr);
    const hmacHex = hmac.digest('hex');
    
    // MD5
    const md5Hash = crypto.createHash('md5').update(hmacHex).digest('hex');
    
    return {
      sign: md5Hash,
      headers: commonArgs
    };
  }

  getHeaders(did) {
    return {
      'User-Agent': this.userAgent,
      'Accept-Encoding': 'gzip',
      'Connection': 'close',
      'X-Requested-With': 'com.hypergryph.skland',
      'dId': did
    };
  }

  async request(method, url, headers, data) {
    for (let i = 0; i < this.maxRetries; i++) {
      try {
        const resp = await axios({
          method,
          url,
          headers,
          data,
          timeout: 30000,
          decompress: true
        });
        return resp.data;
      } catch (e) {
        if (i === this.maxRetries - 1) throw e;
        await new Promise(r => setTimeout(r, 1000));
      }
    }
  }

  async authenticate(token) {
    const did = await this.getDeviceId();
    const headers = this.getHeaders(did);
    
    const resp = await this.request('POST', 
      'https://as.hypergryph.com/user/oauth2/v2/grant',
      headers,
      { appCode: "4ca99fa6b56cc2ba", token, type: 0 }
    );
    
    if (resp.status !== 0) {
      throw new Error(`Auth failed: ${resp.message}`);
    }
    
    return resp.data.code;
  }

  async getCredential(authCode) {
    const did = await this.getDeviceId();
    const headers = this.getHeaders(did);
    
    const resp = await this.request('POST',
      'https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code',
      headers,
      { code: authCode, kind: 1 }
    );
    
    if (resp.code !== 0) {
      throw new Error(`Credential failed: ${resp.message}`);
    }
    
    return { token: resp.data.token, cred: resp.data.cred };
  }

  async getBindings(cred) {
    const did = await this.getDeviceId();
    const url = 'https://zonai.skland.com/api/v1/game/player/binding';
    const path = new URL(url).pathname;
    
    const { sign, headers: commonArgs } = this.generateSignature(cred.token, path, "", did);
    
    const headers = {
      ...this.getHeaders(did),
      cred: cred.cred,
      sign: sign,
      ...commonArgs
    };
    
    const resp = await this.request('GET', url, headers, null);
    
    if (resp.code !== 0) {
      throw new Error(`Binding failed: ${resp.message}`);
    }
    
    const bindings = [];
    for (const item of (resp.data?.list || [])) {
      if (item.appCode !== 'endfield') continue;
      
      for (const binding of (item.bindingList || [])) {
        bindings.push({
          appCode: 'endfield',
          gameName: binding.gameName,
          nickName: binding.nickName,
          channelName: binding.channelName,
          uid: binding.uid,
          gameId: binding.gameId,
          roles: binding.roles || []
        });
      }
    }
    
    return bindings;
  }

  async signIn(cred, binding) {
    const results = [];
    
    if (!binding.roles || binding.roles.length === 0) {
      return [{
        ok: false,
        game: '终末地',
        name: binding.nickName,
        channel: binding.channelName,
        rewards: [],
        error: 'no roles'
      }];
    }
    
    const did = await this.getDeviceId();
    const url = 'https://zonai.skland.com/web/v1/game/endfield/attendance';
    const path = new URL(url).pathname;
    
    for (const role of binding.roles) {
      const roleName = role.nickname || binding.nickName;
      
      const { sign, headers: commonArgs } = this.generateSignature(cred.token, path, "", did);
      
      const headers = {
        ...this.getHeaders(did),
        cred: cred.cred,
        sign: sign,
        'Content-Type': 'application/json',
        'sk-game-role': `3_${role.roleId}_${role.serverId}`,
        referer: 'https://game.skland.com/',
        origin: 'https://game.skland.com/',
        ...commonArgs
      };
      
      try {
        const resp = await this.request('POST', url, headers, {});
        
        if (resp.code === 0) {
          const rewards = [];
          const awardIds = resp.data?.awardIds || [];
          const resourceMap = resp.data?.resourceInfoMap || {};
          
          for (const award of awardIds) {
            const info = resourceMap[award.id];
            if (info) {
              rewards.push(`${info.name}x${info.count}`);
            }
          }
          
          results.push({
            ok: true,
            game: '终末地',
            name: roleName,
            channel: binding.channelName,
            rewards,
            error: ''
          });
        } else {
          results.push({
            ok: false,
            game: '终末地',
            name: roleName,
            channel: binding.channelName,
            rewards: [],
            error: resp.message || 'Unknown error'
          });
        }
      } catch (e) {
        results.push({
          ok: false,
          game: '终末地',
          name: roleName,
          channel: binding.channelName,
          rewards: [],
          error: e.message
        });
      }
    }
    
    return results;
  }

  async run(token) {
    const authCode = await this.authenticate(token);
    const cred = await this.getCredential(authCode);
    const bindings = await this.getBindings(cred);
    
    const allResults = [];
    for (const binding of bindings) {
      const results = await this.signIn(cred, binding);
      allResults.push(...results);
    }
    
    return allResults;
  }
}

class DingTalkNotifier {
  constructor(webhook, secret) {
    this.webhook = webhook;
    this.secret = secret;
  }

  generateSign(timestamp) {
    if (!this.secret) return '';
    const stringToSign = `${timestamp}\n${this.secret}`;
    return crypto.createHmac('sha256', this.secret).update(stringToSign).digest('base64');
  }

  async send(message, title) {
    if (!this.webhook) return false;
    
    const timestamp = Date.now();
    const sign = this.generateSign(timestamp);
    
    let url = this.webhook;
    if (this.secret) {
      const encodedSign = encodeURIComponent(sign);
      url = `${this.webhook}&timestamp=${timestamp}&sign=${encodedSign}`;
    }
    
    try {
      const resp = await axios.post(url, {
        msgtype: 'markdown',
        markdown: { title, text: message }
      }, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 10000
      });
      
      return resp.data?.errcode === 0;
    } catch (e) {
      console.error('DingTalk send failed:', e.message);
      return false;
    }
  }
}

async function main() {
  console.log('Starting Endfield sign-in task');
  
  const tokensEnv = process.env.SKLAND_TOKENS || '';
  const webhook = process.env.DINGTALK_WEBHOOK || '';
  const secret = process.env.DINGTALK_SECRET || '';
  
  if (!tokensEnv) {
    console.error('SKLAND_TOKENS not set');
    process.exit(1);
  }
  
  const tokens = tokensEnv.split(/[,;]/).map(s => s.trim()).filter(s => s);
  
  if (tokens.length === 0) {
    console.error('No valid tokens');
    process.exit(1);
  }
  
  const client = new SklandClient();
  const lines = ['### 📅 森空岛终末地签到', ''];
  
  console.log(`Starting task for ${tokens.length} accounts`);
  
  let allOk = true;
  
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    lines.push(`#### 🌈 账号 ${i + 1}`);
    
    try {
      const results = await client.run(token);
      
      if (results.length === 0) {
        lines.push('- ❌ 未找到绑定角色');
        allOk = false;
      } else {
        for (const result of results) {
          const icon = result.ok ? '✅' : '❌';
          const status = result.ok ? '签到成功' : '签到失败';
          
          let details = '';
          if (result.rewards.length > 0) {
            details = `奖励: ${result.rewards.join(', ')}`;
          } else if (result.error) {
            details = `错误: ${result.error}`;
          }
          
          lines.push(`- ${icon} **${result.name}**: ${status} ${details}`);
          
          if (!result.ok) allOk = false;
        }
      }
    } catch (e) {
      lines.push(`- ❌ **系统错误**: ${e.message}`);
      allOk = false;
    }
    
    lines.push('');
  }
  
  if (webhook) {
    const notifier = new DingTalkNotifier(webhook, secret || null);
    const content = lines.join('\n');
    const status = allOk ? '✅ 全部成功' : '⚠️ 部分失败';
    const now = moment().format('YYYY-MM-DD HH:mm:ss');
    const fullMessage = `${content}\n\n---\n**${status}** | ${now}`;
    
    const success = await notifier.send(fullMessage, '终末地签到通知');
    console.log('DingTalk notify:', success ? 'ok' : 'failed');
  }
  
  console.log('Task completed');
}

main().catch(e => {
  console.error('Error:', e);
  process.exit(1);
});