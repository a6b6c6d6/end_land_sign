use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json::json;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use chrono::Local;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use md5::Md5;
use digest::Digest;
use base64::Engine;
use anyhow::{Result, anyhow, Context};
use log::{info, error};

// 加密库
use aes::Aes128;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use cbc::cipher::block_padding::Pkcs7;
use des::Des;
use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use pkcs8::DecodePublicKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    status: i32,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<AuthData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    code: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CredResponse {
    code: i32,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<CredData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CredData {
    token: String,
    cred: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct BindingResponse {
    code: i32,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<BindingData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BindingData {
    #[serde(default)]
    list: Vec<AppBinding>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppBinding {
    #[serde(rename = "appCode")]
    app_code: String,
    #[serde(default)]
    bindingList: Vec<BindingItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BindingItem {
    #[serde(rename = "gameName", default)]
    game_name: String,
    #[serde(rename = "nickName", default)]
    nick_name: String,
    #[serde(rename = "channelName", default)]
    channel_name: String,
    #[serde(default)]
    uid: String,
    #[serde(rename = "gameId", default)]
    game_id: i32,
    #[serde(default)]
    roles: Vec<RoleInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RoleInfo {
    #[serde(rename = "nickname", default)]
    nickname: String,
    #[serde(rename = "roleId", default)]
    role_id: String,
    #[serde(rename = "serverId", default)]
    server_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignResponse {
    code: i32,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    data: Option<SignData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignData {
    #[serde(rename = "awardIds", default)]
    award_ids: Vec<AwardId>,
    #[serde(rename = "resourceInfoMap", default)]
    resource_info_map: HashMap<String, ResourceInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AwardId {
    #[serde(default)]
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResourceInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    count: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceProfileResponse {
    code: i32,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    detail: Option<DeviceDetail>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceDetail {
    #[serde(rename = "deviceId")]
    device_id: String,
}

#[derive(Debug, Clone)]
struct Credential {
    token: String,
    cred: String,
}

#[derive(Debug, Clone)]
struct Binding {
    app_code: String,
    game_name: String,
    nick_name: String,
    channel_name: String,
    uid: String,
    game_id: i32,
    roles: Vec<RoleInfo>,
}

#[derive(Debug)]
struct SignResult {
    ok: bool,
    game: String,
    name: String,
    channel: String,
    rewards: Vec<String>,
    error: String,
}

const RSA_PUBLIC_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxMNr7n8ZeT0tE1R9j/mPixoinPkeM+k4VGIn/s0k7N5rJAfnZ0eMER+QhwFvshzo0LNmeUkpR8uIlU/GEVr8mN28sKmwd2gpygqj0ePnBmOW4v0ZVwbSYK+izkhVFk2V/doLoMbWy6b+UnA8mkjvg0iYWRByfRsK2gdl7llqCwIDAQAB";

const DES_RULE: [(&str, &str, &str, i32); 25] = [
    ("appId", "DES", "uy7mzc4h", 1),
    ("box", "", "", 0),
    ("canvas", "DES", "snrn887t", 1),
    ("clientSize", "DES", "cpmjjgsu", 1),
    ("organization", "DES", "78moqjfc", 1),
    ("os", "DES", "je6vk6t4", 1),
    ("platform", "DES", "pakxhcd2", 1),
    ("plugins", "DES", "v51m3pzl", 1),
    ("pmf", "DES", "2mdeslu3", 1),
    ("protocol", "", "", 0),
    ("referer", "DES", "y7bmrjlc", 1),
    ("res", "DES", "whxqm2a7", 1),
    ("rtype", "DES", "x8o2h2bl", 1),
    ("sdkver", "DES", "9q3dcxp2", 1),
    ("status", "DES", "2jbrxxw4", 1),
    ("subVersion", "DES", "eo3i2puh", 1),
    ("svm", "DES", "fzj3kaeh", 1),
    ("time", "DES", "q2t3odsk", 1),
    ("timezone", "DES", "1uv05lj5", 1),
    ("tn", "DES", "x9nzj1bp", 1),
    ("trees", "DES", "acfs0xo4", 1),
    ("ua", "DES", "k92crp1t", 1),
    ("url", "DES", "y95hjkoo", 1),
    ("version", "", "", 0),
    ("vpw", "DES", "r9924ab5", 1),
];

const DES_OBFUSCATED_NAMES: [(&str, &str); 25] = [
    ("appId", "xx"),
    ("box", "jf"),
    ("canvas", "yk"),
    ("clientSize", "zx"),
    ("organization", "dp"),
    ("os", "pj"),
    ("platform", "gm"),
    ("plugins", "kq"),
    ("pmf", "vw"),
    ("protocol", "protocol"),
    ("referer", "ab"),
    ("res", "hf"),
    ("rtype", "lo"),
    ("sdkver", "sc"),
    ("status", "an"),
    ("subVersion", "ns"),
    ("svm", "qr"),
    ("time", "nb"),
    ("timezone", "as"),
    ("tn", "py"),
    ("trees", "pi"),
    ("ua", "bj"),
    ("url", "cf"),
    ("version", "version"),
    ("vpw", "ca"),
];

const DES_TARGET_BASE: [(&str, &str); 9] = [
    ("protocol", "102"),
    ("organization", "UWXspnCCJN4sfYlNfqps"),
    ("appId", "default"),
    ("os", "web"),
    ("version", "3.0.0"),
    ("sdkver", "3.0.0"),
    ("box", ""),
    ("rtype", "all"),
    ("subVersion", "1.0.0"),
];

const BROWSER_ENV: [(&str, &str); 9] = [
    ("plugins", "MicrosoftEdgePDFPluginPortableDocumentFormatinternal-pdf-viewer1,MicrosoftEdgePDFViewermhjfbmdgcfjbbpaeojofohoefgiehjai1"),
    ("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0"),
    ("canvas", "259ffe69"),
    ("timezone", "-480"),
    ("platform", "Win32"),
    ("url", "https://www.skland.com/"),
    ("referer", ""),
    ("res", "1920_1080_24_1.25"),
    ("clientSize", "0_0_1080_1920_1920_1080_1920_1080"),
];

const USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 12; SM-A5560 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1";

struct SklandClient {
    client: Client,
    device_id: String,
    user_agent: String,
    retry_count: u32,
}

impl SklandClient {
    fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(SklandClient {
            client,
            device_id: String::new(),
            user_agent: USER_AGENT.to_string(),
            retry_count: 3,
        })
    }

    fn des_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut key_bytes = [0u8; 8];
        let key_len = key.len().min(8);
        key_bytes[..key_len].copy_from_slice(&key[..key_len]);
        
        let key_array = GenericArray::from_slice(&key_bytes);
        let cipher = Des::new(key_array);
        
        let padding_len = 8 - (data.len() % 8);
        let mut padded_data = data.to_vec();
        if padding_len != 8 {
            padded_data.extend(vec![0u8; padding_len]);
        }
        
        let mut result = Vec::new();
        for chunk in padded_data.chunks(8) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }
        
        Ok(result)
    }

    fn aes_encrypt(data: &[u8], key: &[u8]) -> Result<String> {
        let base64_data = base64::engine::general_purpose::STANDARD.encode(data);
        let mut data_bytes = base64_data.into_bytes();
        
        let pad_len = 16 - (data_bytes.len() % 16);
        if pad_len != 16 {
            data_bytes.extend(vec![0u8; pad_len]);
        }
        
        let mut key_bytes = [0u8; 16];
        let key_len = key.len().min(16);
        key_bytes[..key_len].copy_from_slice(&key[..key_len]);
        
        let iv = b"0102030405060708";
        
        let encryptor = Aes128CbcEnc::new_from_slices(&key_bytes, iv)
            .map_err(|e| anyhow!("AES key/IV length error: {:?}", e))?;
        
        let mut buf = data_bytes.clone();
        let len = data_bytes.len();
        buf.resize(len + 16, 0);
        
        let ct = encryptor.encrypt_padded_b2b_mut::<Pkcs7>(&data_bytes, &mut buf)
            .map_err(|e| anyhow!("AES encryption error: {:?}", e))?;
        
        Ok(hex::encode_upper(ct))
    }

    fn get_smid() -> String {
        let time_str = Local::now().format("%Y%m%d%H%M%S").to_string();
        let uid = Uuid::new_v4().to_string();
        
        let mut hasher = Md5::new();
        hasher.update(uid.as_bytes());
        let uid_hash = format!("{:x}", hasher.finalize());
        
        let v = format!("{}{}00", time_str, uid_hash);
        
        let mut hasher2 = Md5::new();
        hasher2.update(format!("smsk_web_{}", v));
        let smsk_web = hasher2.finalize();
        
        let suffix = hex::encode(&smsk_web[..7]);
        format!("{}{}0", v, suffix)
    }

    fn get_tn(data: &HashMap<String, String>) -> String {
        let mut keys: Vec<&String> = data.keys().collect();
        keys.sort();
        
        let mut result = String::new();
        for key in keys {
            if let Some(value) = data.get(key) {
                if let Ok(num) = value.parse::<i64>() {
                    result.push_str(&(num * 10000).to_string());
                } else {
                    result.push_str(value);
                }
            }
        }
        result
    }

    fn apply_des_rules(data: &HashMap<String, String>) -> Result<HashMap<String, String>> {
        let mut result = HashMap::new();
        
        let obfuscated_map: HashMap<&str, &str> = DES_OBFUSCATED_NAMES.iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        
        for (key, value) in data {
            if let Some(rule) = DES_RULE.iter().find(|(k, _, _, _)| k == key) {
                let (_, cipher, des_key, is_encrypt) = rule;
                
                if *is_encrypt == 1 && !cipher.is_empty() {
                    let encrypted = Self::des_encrypt(des_key.as_bytes(), value.as_bytes())?;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(encrypted);
                    if let Some(&obf_name) = obfuscated_map.get(key.as_str()) {
                        result.insert(obf_name.to_string(), b64);
                    }
                } else {
                    if let Some(&obf_name) = obfuscated_map.get(key.as_str()) {
                        result.insert(obf_name.to_string(), value.clone());
                    }
                }
            } else {
                result.insert(key.clone(), value.clone());
            }
        }
        
        Ok(result)
    }

    async fn generate_device_id(&mut self) -> Result<String> {
        if !self.device_id.is_empty() {
            return Ok(self.device_id.clone());
        }

        let uid = Uuid::new_v4().to_string();
        let mut hasher = Md5::new();
        hasher.update(uid.as_bytes());
        let uid_hash = hasher.finalize();
        let pri_id_hex = hex::encode(&uid_hash[..8]);

        let public_key_der = base64::engine::general_purpose::STANDARD.decode(RSA_PUBLIC_KEY)
            .context("Failed to decode RSA public key")?;
        let public_key = RsaPublicKey::from_public_key_der(&public_key_der)
            .context("Failed to parse RSA public key")?;
        
        let encrypted_uid = public_key.encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, uid.as_bytes())
            .context("RSA encryption failed")?;
        let ep_base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted_uid);

        let in_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Time went backwards")?
            .as_millis() as i64;
            
        let mut des_target = HashMap::new();
        
        for (k, v) in DES_TARGET_BASE.iter() {
            des_target.insert(k.to_string(), v.to_string());
        }
        
        for (k, v) in BROWSER_ENV.iter() {
            des_target.insert(k.to_string(), v.to_string());
        }
        
        des_target.insert("smid".to_string(), Self::get_smid());
        des_target.insert("vpw".to_string(), Uuid::new_v4().to_string());
        des_target.insert("trees".to_string(), Uuid::new_v4().to_string());
        des_target.insert("svm".to_string(), in_ms.to_string());
        des_target.insert("pmf".to_string(), in_ms.to_string());
        des_target.insert("time".to_string(), in_ms.to_string());

        let tn_input = Self::get_tn(&des_target);
        let mut tn_hasher = Md5::new();
        tn_hasher.update(tn_input.as_bytes());
        let tn = format!("{:x}", tn_hasher.finalize());
        des_target.insert("tn".to_string(), tn);

        let des_result = Self::apply_des_rules(&des_target)?;

        let json_str = serde_json::to_string(&des_result)
            .context("JSON serialization failed")?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(2));
        encoder.write_all(json_str.as_bytes())
            .context("Gzip compression failed")?;
        let compressed = encoder.finish()
            .context("Gzip finish failed")?;

        let encrypted = Self::aes_encrypt(&compressed, pri_id_hex.as_bytes())?;

        let response: DeviceProfileResponse = self.client
            .post("https://fp-it.portal101.cn/deviceprofile/v4")
            .json(&json!({
                "appId": "default",
                "compress": 2,
                "data": encrypted,
                "encode": 5,
                "ep": ep_base64,
                "organization": "UWXspnCCJN4sfYlNfqps",
                "os": "web",
            }))
            .send()
            .await
            .context("Failed to request device ID")?
            .json()
            .await
            .context("Failed to parse device ID response")?;

        if response.code != 1100 {
            return Err(anyhow!("Device ID generation failed: {:?}", response.message));
        }

        let did = response.detail
            .map(|d| format!("B{}", d.device_id))
            .ok_or_else(|| anyhow!("No device ID in response"))?;
            
        self.device_id = did.clone();
        Ok(did)
    }

    async fn get_or_generate_device_id(&mut self) -> Result<String> {
        if self.device_id.is_empty() {
            self.generate_device_id().await
        } else {
            Ok(self.device_id.clone())
        }
    }

    fn generate_signature(&self, token: &str, path: &str, body: &str, did: &str) -> Result<(String, HashMap<String, String>)> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Time went backwards")?
            .as_secs();

        let common_args = json!({
            "platform": "3",
            "timestamp": timestamp.to_string(),
            "dId": did,
            "vName": "1.0.0"
        });

        let sign_str = format!("{}{}{}{}", path, body, timestamp, common_args);

        let mut mac = <HmacSha256 as Mac>::new_from_slice(token.as_bytes())
            .map_err(|e| anyhow!("HMAC error: {:?}", e))?;
        mac.update(sign_str.as_bytes());
        let hmac_result = mac.finalize().into_bytes();
        let hmac_hex = format!("{:x}", hmac_result);

        let mut hasher = Md5::new();
        hasher.update(hmac_hex.as_bytes());
        let md5_result = hasher.finalize();
        let sign = format!("{:x}", md5_result);

        let mut headers = HashMap::new();
        headers.insert("platform".to_string(), "3".to_string());
        headers.insert("timestamp".to_string(), timestamp.to_string());
        headers.insert("dId".to_string(), did.to_string());
        headers.insert("vName".to_string(), "1.0.0".to_string());

        Ok((sign, headers))
    }

    fn create_headers(&self, did: &str) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_str(&self.user_agent)?);
        headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
        headers.insert("Connection", HeaderValue::from_static("close"));
        headers.insert("X-Requested-With", HeaderValue::from_static("com.hypergryph.skland"));
        headers.insert("dId", HeaderValue::from_str(did)?);
        Ok(headers)
    }

    async fn request_with_retry<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        url: &str,
        headers: Option<HeaderMap>,
        body: Option<serde_json::Value>,
    ) -> Result<T> {
        let mut last_error = None;

        for i in 0..self.retry_count {
            let request = if method == "GET" {
                self.client.get(url)
            } else {
                self.client.post(url)
            };

            let mut request = request;

            if let Some(ref headers) = headers {
                request = request.headers(headers.clone());
            }

            if let Some(ref body) = body {
                request = request.json(body);
            }

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<T>().await {
                            Ok(data) => return Ok(data),
                            Err(e) => last_error = Some(anyhow!("JSON parse error: {}", e)),
                        }
                    } else {
                        last_error = Some(anyhow!("HTTP error: {}", response.status()));
                    }
                }
                Err(e) => last_error = Some(anyhow!("Request error: {}", e)),
            }

            if i < self.retry_count - 1 {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("Request failed after {} retries", self.retry_count)))
    }

    async fn authenticate(&mut self, token: &str) -> Result<String> {
        let did = self.get_or_generate_device_id().await?;
        let headers = self.create_headers(&did)?;
        let url = "https://as.hypergryph.com/user/oauth2/v2/grant";

        let body = json!({
            "appCode": "4ca99fa6b56cc2ba",
            "token": token,
            "type": 0
        });

        let response: AuthResponse = self
            .request_with_retry("POST", url, Some(headers), Some(body))
            .await
            .context("Authentication failed")?;

        if response.status != 0 {
            return Err(anyhow!("Auth failed: {}", response.message.unwrap_or_default()));
        }

        response.data.map(|d| d.code).ok_or_else(|| anyhow!("No auth data"))
    }

    async fn get_credential(&mut self, auth_code: &str) -> Result<Credential> {
        let did = self.get_or_generate_device_id().await?;
        let headers = self.create_headers(&did)?;
        let url = "https://zonai.skland.com/web/v1/user/auth/generate_cred_by_code";

        let body = json!({
            "code": auth_code,
            "kind": 1
        });

        let response: CredResponse = self
            .request_with_retry("POST", url, Some(headers), Some(body))
            .await
            .context("Get credential failed")?;

        if response.code != 0 {
            return Err(anyhow!("Cred failed: {}", response.message.unwrap_or_default()));
        }

        response.data.map(|d| Credential {
            token: d.token,
            cred: d.cred,
        }).ok_or_else(|| anyhow!("No credential data"))
    }

    async fn get_bindings(&mut self, cred: &Credential) -> Result<Vec<Binding>> {
        let did = self.get_or_generate_device_id().await?;
        let url = "https://zonai.skland.com/api/v1/game/player/binding";
        let parsed_url = url::Url::parse(url).context("Invalid URL")?;
        let path = parsed_url.path();

        let (sign, common_args) = self.generate_signature(&cred.token, path, "", &did)?;

        let mut headers = self.create_headers(&did)?;
        headers.insert("cred", HeaderValue::from_str(&cred.cred)?);
        headers.insert("sign", HeaderValue::from_str(&sign)?);

        for (key, value) in common_args {
            headers.insert(
                key.parse::<reqwest::header::HeaderName>()?, 
                HeaderValue::from_str(&value)?
            );
        }

        let response: BindingResponse = self
            .request_with_retry("GET", url, Some(headers), None)
            .await
            .context("Get bindings failed")?;

        if response.code != 0 {
            return Err(anyhow!("Binding failed: {}", response.message.unwrap_or_default()));
        }

        let mut bindings = Vec::new();

        if let Some(data) = response.data {
            for app in data.list {
                if app.app_code != "endfield" {
                    continue;
                }

                for item in app.bindingList {
                    bindings.push(Binding {
                        app_code: "endfield".to_string(),
                        game_name: item.game_name,
                        nick_name: item.nick_name,
                        channel_name: item.channel_name,
                        uid: item.uid,
                        game_id: item.game_id,
                        roles: item.roles,
                    });
                }
            }
        }

        Ok(bindings)
    }

    async fn sign_in(&mut self, cred: &Credential, binding: &Binding) -> Result<Vec<SignResult>> {
        let mut results = Vec::new();

        if binding.roles.is_empty() {
            results.push(SignResult {
                ok: false,
                game: "终末地".to_string(),
                name: binding.nick_name.clone(),
                channel: binding.channel_name.clone(),
                rewards: Vec::new(),
                error: "no roles".to_string(),
            });
            return Ok(results);
        }

        let did = self.get_or_generate_device_id().await?;
        let url = "https://zonai.skland.com/web/v1/game/endfield/attendance";
        let parsed_url = url::Url::parse(url).context("Invalid URL")?;
        let path = parsed_url.path();

        for role in &binding.roles {
            let role_name = if !role.nickname.is_empty() {
                role.nickname.clone()
            } else {
                binding.nick_name.clone()
            };

            let (sign, common_args) = self.generate_signature(&cred.token, path, "", &did)?;

            let mut headers = self.create_headers(&did)?;
            headers.insert("cred", HeaderValue::from_str(&cred.cred)?);
            headers.insert("sign", HeaderValue::from_str(&sign)?);
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(
                "sk-game-role",
                HeaderValue::from_str(&format!("3_{}_{}", role.role_id, role.server_id))?,
            );
            headers.insert("referer", HeaderValue::from_static("https://game.skland.com/"));
            headers.insert("origin", HeaderValue::from_static("https://game.skland.com/"));

            for (key, value) in common_args {
                headers.insert(
                    key.parse::<reqwest::header::HeaderName>()?, 
                    HeaderValue::from_str(&value)?
                );
            }

            let result = match self.client.post(url).headers(headers).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<SignResponse>().await {
                            Ok(sign_response) => {
                                if sign_response.code == 0 {
                                    let mut rewards = Vec::new();

                                    if let Some(data) = sign_response.data {
                                        for award_id in data.award_ids {
                                            if let Some(resource) = data.resource_info_map.get(&award_id.id) {
                                                rewards.push(format!("{}x{}", resource.name, resource.count));
                                            }
                                        }
                                    }

                                    SignResult {
                                        ok: true,
                                        game: "终末地".to_string(),
                                        name: role_name,
                                        channel: binding.channel_name.clone(),
                                        rewards,
                                        error: String::new(),
                                    }
                                } else {
                                    SignResult {
                                        ok: false,
                                        game: "终末地".to_string(),
                                        name: role_name,
                                        channel: binding.channel_name.clone(),
                                        rewards: Vec::new(),
                                        error: sign_response.message.unwrap_or_default(),
                                    }
                                }
                            }
                            Err(e) => SignResult {
                                ok: false,
                                game: "终末地".to_string(),
                                name: role_name,
                                channel: binding.channel_name.clone(),
                                rewards: Vec::new(),
                                error: format!("JSON parse error: {}", e),
                            },
                        }
                    } else {
                        SignResult {
                            ok: false,
                            game: "终末地".to_string(),
                            name: role_name,
                            channel: binding.channel_name.clone(),
                            rewards: Vec::new(),
                            error: format!("HTTP error: {}", response.status()),
                        }
                    }
                }
                Err(e) => SignResult {
                    ok: false,
                    game: "终末地".to_string(),
                    name: role_name,
                    channel: binding.channel_name.clone(),
                    rewards: Vec::new(),
                    error: format!("Request error: {}", e),
                },
            };

            results.push(result);
        }

        Ok(results)
    }

    async fn run(&mut self, token: &str) -> Result<Vec<SignResult>> {
        let auth_code = self.authenticate(token).await?;
        let credential = self.get_credential(&auth_code).await?;
        let bindings = self.get_bindings(&credential).await?;

        let mut all_results = Vec::new();

        for binding in bindings {
            let results = self.sign_in(&credential, &binding).await?;
            all_results.extend(results);
        }

        Ok(all_results)
    }
}

struct DingTalkNotifier {
    webhook: String,
    secret: Option<String>,
    client: Client,
}

impl DingTalkNotifier {
    fn new(webhook: &str, secret: Option<&str>) -> Self {
        DingTalkNotifier {
            webhook: webhook.to_string(),
            secret: secret.map(|s| s.to_string()).filter(|s| !s.is_empty()),
            client: Client::new(),
        }
    }

    fn generate_sign(&self, timestamp: i64) -> Result<String> {
        if let Some(secret) = &self.secret {
            let string_to_sign = format!("{}\n{}", timestamp, secret);
            
            let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow!("HMAC error: {:?}", e))?;
            mac.update(string_to_sign.as_bytes());
            let result = mac.finalize().into_bytes();
            
            Ok(base64::engine::general_purpose::STANDARD.encode(result))
        } else {
            Ok(String::new())
        }
    }

    async fn send(&self, message: &str, title: &str) -> Result<bool> {
        if self.webhook.is_empty() {
            return Ok(false);
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Time went backwards")?
            .as_secs() as i64 * 1000;

        let sign = self.generate_sign(timestamp)?;
        let url = if self.secret.is_some() && !sign.is_empty() {
            let sign_encoded = urlencoding::encode(&sign);
            format!("{}&timestamp={}&sign={}", self.webhook, timestamp, sign_encoded)
        } else {
            self.webhook.clone()
        };

        let data = json!({
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": message
            }
        });

        match self.client.post(&url)
            .json(&data)
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<HashMap<String, serde_json::Value>>().await {
                        Ok(json) => {
                            if let Some(errcode) = json.get("errcode").and_then(|v| v.as_i64()) {
                                return Ok(errcode == 0);
                            }
                            Ok(false)
                        }
                        Err(_) => Ok(false),
                    }
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                error!("DingTalk send failed: {}", e);
                Ok(false)
            }
        }
    }
}

async fn run_main() -> Result<()> {
    env_logger::init();
    info!("Starting Endfield sign-in task");

    let tokens_env = env::var("SKLAND_TOKENS").unwrap_or_default();
    let webhook = env::var("DINGTALK_WEBHOOK").unwrap_or_default();
    let secret = env::var("DINGTALK_SECRET").unwrap_or_default();

    if tokens_env.is_empty() {
        error!("SKLAND_TOKENS not set");
        return Err(anyhow!("SKLAND_TOKENS not set"));
    }

    let tokens: Vec<String> = tokens_env
        .replace(';', ",")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if tokens.is_empty() {
        error!("No valid tokens");
        return Err(anyhow!("No valid tokens"));
    }

    let mut client = SklandClient::new()?;
    let mut lines = vec![
        "### 📅 森空岛终末地签到".to_string(),
        String::new(),
    ];

    info!("Starting task for {} accounts", tokens.len());

    let mut all_ok = true;

    for (i, token) in tokens.iter().enumerate() {
        let account_num = i + 1;
        lines.push(format!("#### 🌈 账号 {}", account_num));

        match client.run(token).await {
            Ok(results) => {
                if results.is_empty() {
                    lines.push("- ❌ 未找到绑定角色".to_string());
                    all_ok = false;
                } else {
                    for result in results {
                        let icon = if result.ok { "✅" } else { "❌" };
                        let status = if result.ok { "签到成功" } else { "签到失败" };

                        let details = if !result.rewards.is_empty() {
                            format!("奖励: {}", result.rewards.join(", "))
                        } else if !result.error.is_empty() {
                            format!("错误: {}", result.error)
                        } else {
                            String::new()
                        };

                        lines.push(format!("- {} **{}**: {} {}", icon, result.name, status, details));

                        if !result.ok {
                            all_ok = false;
                        }
                    }
                }
            }
            Err(e) => {
                lines.push(format!("- ❌ **系统错误**: {}", e));
                all_ok = false;
            }
        }

        lines.push(String::new());
    }

    if !webhook.is_empty() {
        let notifier = DingTalkNotifier::new(&webhook, if secret.is_empty() { None } else { Some(&secret) });

        let content = lines.join("\n");
        let status = if all_ok { "✅ 全部成功" } else { "⚠️ 部分失败" };
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let full_message = format!("{}\n\n---\n**{}** | {}", content, status, now);

        match notifier.send(&full_message, "终末地签到通知").await {
            Ok(success) => info!("DingTalk notify: {}", if success { "ok" } else { "failed" }),
            Err(e) => error!("Failed to send DingTalk notification: {}", e),
        }
    }

    info!("Task completed");
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_main().await {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}
