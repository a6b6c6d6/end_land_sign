const axios = require('axios');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');
const zlib = require('zlib');
const moment = require('moment');
const { URL } = require('url');

// ==================== 用户配置区域 ====================
const SKLAND_TOKENS = process.env.SKLAND_TOKENS || "";
const DINGTALK_WEBHOOK = process.env.DINGTALK_WEBHOOK || "";
const DINGTALK_SECRET = process.env.DINGTALK_SECRET || "";
const SKLAND_DEVICE_ID = process.env.SKLAND_DEVICE_ID || "";
// 设置为 true 则自动获取代理（GitHub Actions 必须设为 true）
const USE_PROXY = process.env.USE_PROXY === "true" || false;
// =====================================================

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
  "protocol": 102,
  "organization": "UWXspnCCJN4sfYlNfqps",
  "appId": "default",
  "os": "web",
  "version": "3.0.0",
  "sdkver": "3.0.0",
  "box": "",
  "rtype": "all",
  "subVersion": "1.0.0",
  "time": 0,
};

const BROWSER_ENV = {
  "plugins": "MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1",
  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
  "canvas": "259ffe69",
  "timezone": -480,
  "platform": "Win32",
  "url": "https://www.skland.com/",
  "referer": "",
  "res": "1920_1080_24_1.25",
  "clientSize": "0_0_1080_1920_1920_1080_1920_1080",
  "status": "0011",
};

const USER_AGENT = "Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1";

// ==================== 代理获取模块 ====================

class ProxyManager {
  constructor() {
    this.workingProxy = null;
  }

  async fetchProxies() {
    console.log("正在获取代理列表...");
    try {
      // 使用 89ip 免费代理 API
      const apiUrl = 'https://api.89ip.cn/tqdl.html?api=1&num=4000&port=&address=&isp=';
      const resp = await axios.get(apiUrl, { timeout: 10000 });
      const text = resp.data;
      
      // 正则提取 IP:Port
      const proxies = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:\d+\b/g) || [];
      console.log(`获取到 ${proxies.length} 个代理`);
      return [...new Set(proxies)]; // 去重
    } catch (e) {
      console.error("获取代理列表失败:", e.message);
      return [];
    }
  }

  async checkProxy(proxy) {
    const [host, port] = proxy.split(':');
    try {
      const start = Date.now();
      const proxyUrl = `http://${proxy}`;
      
      // 测试代理：访问 httpbin.org/ip
      await axios.get('http://httpbin.org/ip', {
        proxy: {
          protocol: 'http',
          host: host,
          port: parseInt(port)
        },
        timeout: 3000, // 3秒超时
        headers: {
          'User-Agent': 'Mozilla/5.0'
        }
      });
      
      const delay = Date.now() - start;
      return { proxy, delay };
    } catch (e) {
      return null;
    }
  }

  async getWorkingProxy(maxCheck = 20) {
    if (!USE_PROXY) return null;
    
    console.log("开始检测代理可用性...");
    const proxies = await this.fetchProxies();
    if (proxies.length === 0) return null;

    // 只检测前 maxCheck 个，避免耗时过长
    const checkList = proxies.slice(0, maxCheck);
    
    // 并发检测（最多10个并发）
    const batchSize = 10;
    for (let i = 0; i < checkList.length; i += batchSize) {
      const batch = checkList.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map(p => this.checkProxy(p))
      );
      
      // 返回第一个可用的
      const working = results.find(r => r !== null);
      if (working) {
        console.log(`✓ 找到可用代理: ${working.proxy} (延迟${working.delay}ms)`);
        this.workingProxy = working.proxy;
        return this.workingProxy;
      }
    }
    
    console.log("未找到可用代理，将使用直连（可能失败）");
    return null;
  }

  getAxiosProxyConfig() {
    if (!this.workingProxy) return undefined;
    
    const [host, port] = this.workingProxy.split(':');
    return {
      protocol: 'http',
      host: host,
      port: parseInt(port)
    };
  }
}

// ==================== 原签到逻辑（修改支持代理）====================

function uuidv4() {
  return crypto.randomUUID();
}

function desEncrypt(key, data) {
  const keyStr = key.slice(0, 8).padEnd(8, '\0');
  const keyHex = CryptoJS.enc.Utf8.parse(keyStr);
  const dataHex = CryptoJS.enc.Utf8.parse(data);
  
  const encrypted = CryptoJS.DES.encrypt(dataHex, keyHex, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.ZeroPadding
  });
  
  return Buffer.from(encrypted.ciphertext.toString(CryptoJS.enc.Base64), 'base64');
}

function aesEncrypt(data, key) {
  const base64Data = data.toString('base64');
  
  const keyBuffer = Buffer.alloc(16);
  Buffer.from(key).copy(keyBuffer);
  
  const iv = Buffer.from("0102030405060708");
  
  const cipher = crypto.createCipheriv('aes-128-cbc', keyBuffer, iv);
  let encrypted = cipher.update(base64Data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return encrypted.toUpperCase();
}

function getSmid() {
  const timeStr = moment().format('YYYYMMDDHHmmss');
  const uid = uuidv4();
  const uidHash = crypto.createHash('md5').update(uid).digest('hex');
  const v = `${timeStr}${uidHash}00`;
  const smskWeb = crypto.createHash('md5').update(`smsk_web_${v}`).digest();
  const suffix = smskWeb.slice(0, 7).toString('hex');
  return `${v}${suffix}0`;
}

function getTn(data) {
  const sortedKeys = Object.keys(data).sort();
  let result = "";
  for (const key of sortedKeys) {
    const value = data[key];
    if (typeof value === 'number') {
      result += (value * 10000).toString();
    } else if (typeof value === 'object' && value !== null) {
      result += getTn(value);
    } else {
      result += value ? value.toString() : "";
    }
  }
  return result;
}

function applyDesRules(data) {
  const result = {};
  for (const [key, value] of Object.entries(data)) {
    const strValue = value !== undefined && value !== null ? value.toString() : "";
    const rule = DES_RULE[key];
    
    if (rule) {
      if (rule.is_encrypt === 1) {
        const encrypted = desEncrypt(rule.key, strValue);
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
  constructor(proxyManager) {
    this.deviceId = SKLAND_DEVICE_ID || "";
    this.userAgent = USER_AGENT;
    this.maxRetries = 3;
    this.proxyManager = proxyManager;
  }

  async getDeviceId() {
    if (this.deviceId) return this.deviceId;
    
    console.log('生成新的设备 ID...');
    const uid = uuidv4();
    const uidHash = crypto.createHash('md5').update(uid).digest();
    const priIdHex = uidHash.slice(0, 8).toString('hex');

    const publicKey = crypto.createPublicKey({
      key: Buffer.from(RSA_PUBLIC_KEY, 'base64'),
      format: 'der',
      type: 'spki'
    });
    
    const encryptedUid = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      },
      Buffer.from(uid)
    ).toString('base64');

    const epBase64 = encryptedUid;

    const inMs = Date.now();
    const desTarget = {
      ...DES_TARGET_BASE,
      ...BROWSER_ENV,
      smid: getSmid(),
      vpw: uuidv4(),
      trees: uuidv4(),
      svm: inMs,
      pmf: inMs,
      time: inMs
    };

    const tnInput = getTn(desTarget);
    const tn = crypto.createHash('md5').update(tnInput).digest('hex');
    desTarget.tn = tn;

    const desResult = applyDesRules(desTarget);
    
    const jsonStr = JSON.stringify(desResult);
    const compressed = zlib.gzipSync(jsonStr, { level: 2 });
    
    const encrypted = aesEncrypt(compressed, priIdHex);

    try {
      const proxyConfig = this.proxyManager ? this.proxyManager.getAxiosProxyConfig() : undefined;
      
      const resp = await axios({
        method: 'POST',
        url: 'https://fp-it.portal101.cn/deviceprofile/v4',
        data: {
          appId: "default",
          compress: 2,
          data: encrypted,
          encode: 5,
          ep: epBase64,
          organization: "UWXspnCCJN4sfYlNfqps",
          os: "web",
        },
        headers: { 'Content-Type': 'application/json' },
        timeout: 30000,
        proxy: proxyConfig
      });

      if (resp.data.code !== 1100) {
        throw new Error(`设备 ID 生成失败: ${JSON.stringify(resp.data)}`);
      }

      this.deviceId = `B${resp.data.detail.deviceId}`;
      console.log('设备 ID 生成成功');
      return this.deviceId;
    } catch (e) {
      console.error('设备 ID 生成错误:', e.message);
      throw e;
    }
  }

  generateSignature(token, path, body, did) {
    const timestamp = Math.floor(Date.now() / 1000);
    const headerCa = {
      platform: "3",
      timestamp: timestamp.toString(),
      dId: did,
      vName: "1.0.0"
    };
    
    const headerCaStr = JSON.stringify(headerCa);
    const signStr = `${path}${body || ""}${timestamp}${headerCaStr}`;
    
    const hmac = crypto.createHmac('sha256', token);
    hmac.update(signStr);
    const hmacHex = hmac.digest('hex');
    
    const md5Hash = crypto.createHash('md5').update(hmacHex).digest('hex');
    
    return {
      sign: md5Hash,
      headers: headerCa
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
    const proxyConfig = this.proxyManager ? this.proxyManager.getAxiosProxyConfig() : undefined;
    
    for (let i = 0; i < this.maxRetries; i++) {
      try {
        const config = {
          method,
          url,
          headers,
          timeout: 30000,
          decompress: true,
          proxy: proxyConfig
        };
        
        if (data !== undefined && data !== null) {
          config.data = data;
        }
        
        const resp = await axios(config);
        return resp.data;
      } catch (e) {
        if (i === this.maxRetries - 1) throw e;
        console.log(`请求失败，第 ${i + 1} 次重试...`);
        await new Promise(r => setTimeout(r, 1000));
      }
    }
  }

  async authenticate(token) {
    const did = await this.getDeviceId();
    const headers = this.getHeaders(did);
    
    console.log('正在认证...');
    const resp = await this.request('POST', 
      'https://as.hypergryph.com/user/oauth2/v2/grant',
      headers,
      { appCode: "4ca99fa6b56cc2ba", token, type: 0 }
    );
    
    if (resp.status !== 0) {
      throw new Error(`认证失败: ${resp.message || JSON.stringify(resp)}`);
    }
    
    console.log('认证成功');
    return resp.data.code;
  }

  async getCredential(authCode) {
    const did = await this.getDeviceId();
    const headers = this.getHeaders(did);
    
    console.log('正在获取凭证...');
    const resp = await this.request('POST',
      'https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code',
      headers,
      { code: authCode, kind: 1 }
    );
    
    if (resp.code !== 0) {
      throw new Error(`获取凭证失败: ${resp.message || JSON.stringify(resp)}`);
    }
    
    console.log('获取凭证成功');
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
    
    console.log('正在查询绑定角色...');
    const resp = await this.request('GET', url, headers, null);
    
    if (resp.code !== 0) {
      const msg = resp.message || "未知错误";
      if (msg === "用户未登录") {
        throw new Error("用户登录已过期，请重新获取 Token");
      }
      throw new Error(`查询绑定失败: ${msg}`);
    }
    
    const bindings = [];
    for (const item of (resp.data?.list || [])) {
      const appCode = item.appCode;
      if (appCode !== 'endfield') continue;
      
      for (const binding of (item.bindingList || [])) {
        bindings.push({
          appCode: appCode,
          gameName: binding.gameName,
          nickName: binding.nickName,
          channelName: binding.channelName,
          uid: binding.uid,
          gameId: binding.gameId,
          roles: binding.roles || []
        });
      }
    }
    
    console.log(`找到 ${bindings.length} 个终末地绑定`);
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
        error: '该账号没有绑定终末地角色'
      }];
    }
    
    const did = await this.getDeviceId();
    const url = 'https://zonai.skland.com/web/v1/game/endfield/attendance';
    const path = new URL(url).pathname;
    
    for (const role of binding.roles) {
      const roleName = role.nickname || binding.nickName;
      const roleId = role.roleId || "";
      const serverId = role.serverId || "";
      
      const { sign, headers: commonArgs } = this.generateSignature(cred.token, path, "", did);
      
      const headers = {
        ...this.getHeaders(did),
        cred: cred.cred,
        sign: sign,
        'Content-Type': 'application/json',
        'sk-game-role': `3_${roleId}_${serverId}`,
        referer: 'https://game.skland.com/',
        origin: 'https://game.skland.com/',
        ...commonArgs
      };
      
      try {
        console.log(`正在为角色 [${roleName}] 签到...`);
        const resp = await this.request('POST', url, headers, null);
        
        if (resp.code === 0) {
          const rewards = [];
          const awardIds = resp.data?.awardIds || [];
          const resourceMap = resp.data?.resourceInfoMap || {};
          
          for (const award of awardIds) {
            const aid = award.id;
            if (aid in resourceMap) {
              const info = resourceMap[aid];
              rewards.push(`${info.name}x${info.count}`);
            }
          }
          
          console.log(`✅ ${roleName} 签到成功`);
          results.push({
            ok: true,
            game: '终末地',
            name: roleName,
            channel: binding.channelName,
            rewards,
            error: ''
          });
        } else {
          const errorMsg = resp.message || '未知错误';
          const isSigned = errorMsg.includes('已签到') || errorMsg.includes('重复') || errorMsg.includes('already');
          
          results.push({
            ok: false,
            game: '终末地',
            name: roleName,
            channel: binding.channelName,
            rewards: [],
            error: errorMsg,
            isSigned: isSigned
          });
        }
      } catch (e) {
        console.log(`❌ ${roleName} 请求错误: ${e.message}`);
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
    try {
      const authCode = await this.authenticate(token);
      const cred = await this.getCredential(authCode);
      const bindings = await this.getBindings(cred);
      
      if (bindings.length === 0) {
        console.log('⚠️ 没有找到终末地游戏绑定');
        return [];
      }
      
      const allResults = [];
      for (const binding of bindings) {
        const results = await this.signIn(cred, binding);
        allResults.push(...results);
      }
      
      return allResults;
    } catch (error) {
      console.error('运行错误:', error.message);
      throw error;
    }
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
      console.error('钉钉发送失败:', e.message);
      return false;
    }
  }
}

// ==================== 主程序 ====================

async function main() {
  console.log('=== 森空岛终末地签到 ===');
  console.log('时间:', moment().format('YYYY-MM-DD HH:mm:ss'));
  console.log('');
  
  const tokensEnv = SKLAND_TOKENS || '';
  const webhook = DINGTALK_WEBHOOK || '';
  const secret = DINGTALK_SECRET || '';
  
  if (!tokensEnv) {
    console.error('❌ 错误：请在代码顶部的 SKLAND_TOKENS 处填写你的 Token');
    process.exit(1);
  }
  
  const tokens = tokensEnv.split(/[,;]/).map(s => s.trim()).filter(s => s);
  
  if (tokens.length === 0) {
    console.error('❌ 没有有效的 Token');
    process.exit(1);
  }
  
  // 初始化代理管理器（如果需要）
  const proxyManager = USE_PROXY ? new ProxyManager() : null;
  if (USE_PROXY) {
    await proxyManager.getWorkingProxy(20); // 检测前20个代理
    console.log('');
  }
  
  console.log(`共 ${tokens.length} 个账号`);
  console.log('');
  
  const client = new SklandClient(proxyManager);
  const lines = ['### 📅 森空岛终末地签到', ''];
  
  let allOk = true;
  
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    lines.push(`#### 🌈 账号 ${i + 1}`);
    console.log(`--- 开始处理账号 ${i + 1} ---`);
    
    try {
      const results = await client.run(token);
      
      if (results.length === 0) {
        lines.push('- ⚠️ 未找到终末地角色绑定');
        allOk = false;
      } else {
        for (const result of results) {
          const isSignedAlready = !result.ok && result.isSigned;
          
          let icon, statusText, detail;
          
          if (result.ok) {
            icon = '✅';
            statusText = '成功';
            detail = result.rewards.length > 0 ? ` (${result.rewards.join(', ')})` : '';
          } else if (isSignedAlready) {
            icon = '✅';
            statusText = '已签';
            detail = '';
          } else {
            icon = '❌';
            statusText = '失败';
            detail = ` (${result.error})`;
          }
          
          const line = `${icon} ${result.game}: ${statusText}${detail}`;
          lines.push(`- ${line}`);
          console.log(`  ${line}`);
          
          if (!result.ok && !isSignedAlready) allOk = false;
        }
      }
    } catch (e) {
      console.error(`账号 ${i + 1} 错误:`, e.message);
      lines.push(`- ❌ **系统错误**: ${e.message}`);
      allOk = false;
    }
    
    lines.push('');
    console.log('');
  }
  
  console.log('=== 签到结果汇总 ===');
  console.log(lines.join('\n'));
  
  if (webhook) {
    console.log('正在发送钉钉通知...');
    const notifier = new DingTalkNotifier(webhook, secret || null);
    const content = lines.join('\n');
    const status = allOk ? '✅ 全部成功' : '⚠️ 部分失败';
    const now = moment().format('YYYY-MM-DD HH:mm:ss');
    const fullMessage = `${content}\n\n---\n**${status}** | ${now}`;
    
    const success = await notifier.send(fullMessage, '终末地签到通知');
    console.log('钉钉通知:', success ? '发送成功' : '发送失败');
  }
  
  console.log('');
  console.log('=== 任务完成 ===');
}

main().catch(e => {
  console.error('程序异常:', e);
  process.exit(1);
});

