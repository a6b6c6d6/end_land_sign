use std::collections::HashMap;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use serde_json::json;
use reqwest::Client;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use chrono::Local;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use md5::{Md5, Digest};
use base64::Engine;
use anyhow::{Result, anyhow, Context};
use log::{info, error, warn};

type HmacSha256 = Hmac<Sha256>;

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

        let device_id = Self::generate_device_id()?;

        Ok(SklandClient {
            client,
            device_id,
            user_agent: "Mozilla/5.0 (Linux; Android 12; SM-A5560) AppleWebKit/537.36 Chrome/101.0.4951.61 Safari/537.36; SKLand/1.52.1".to_string(),
            retry_count: 3,
        })
    }

    fn generate_device_id() -> Result<String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Time went backwards")?
            .as_millis();

        let random_str: String = (0..16)
            .map(|i| (b'A' + (i % 26) as u8) as char)
            .collect();

        let mut hasher = Md5::new();
        hasher.update(format!("{}{}", timestamp, random_str));
        let result = hasher.finalize();
        let hex = format!("{:x}", result);

        Ok(format!("B{}", &hex[..16.min(hex.len())].to_uppercase()))
    }

    fn generate_signature(&self, token: &str, path: &str, body: &str) -> Result<(String, HashMap<String, String>)> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("Time went backwards")?
            .as_secs();

        let common_args = json!({
            "platform": "3",
            "timestamp": timestamp.to_string(),
            "dId": self.device_id,
            "vName": "1.0.0"
        });

        let sign_str = format!("{}{}{}{}", path, body, timestamp, common_args);

        let mut mac = HmacSha256::new_from_slice(token.as_bytes())
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
        headers.insert("dId".to_string(), self.device_id.clone());
        headers.insert("vName".to_string(), "1.0.0".to_string());

        Ok((sign, headers))
    }

    fn create_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&self.user_agent)?);
        headers.insert("Accept-Encoding", HeaderValue::from_static("gzip"));
        headers.insert("Connection", HeaderValue::from_static("close"));
        headers.insert("X-Requested-With", HeaderValue::from_static("com.hypergryph.skland"));
        headers.insert("dId", HeaderValue::from_str(&self.device_id)?);
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

    async fn authenticate(&self, token: &str) -> Result<String> {
        let headers = self.create_headers()?;
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

    async fn get_credential(&self, auth_code: &str) -> Result<Credential> {
        let headers = self.create_headers()?;
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

    async fn get_bindings(&self, cred: &Credential) -> Result<Vec<Binding>> {
        let url = "https://zonai.skland.com/api/v1/game/player/binding";
        let parsed_url = url::Url::parse(url).context("Invalid URL")?;
        let path = parsed_url.path();

        let (sign, common_args) = self.generate_signature(&cred.token, path, "")?;

        let mut headers = self.create_headers()?;
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
    async fn sign_in(&self, cred: &Credential, binding: &Binding) -> Result<Vec<SignResult>> {
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

        let url = "https://zonai.skland.com/web/v1/game/endfield/attendance";
        let parsed_url = url::Url::parse(url).context("Invalid URL")?;
        let path = parsed_url.path();

        for role in &binding.roles {
            let role_name = if !role.nickname.is_empty() {
                role.nickname.clone()
            } else {
                binding.nick_name.clone()
            };

            let (sign, common_args) = self.generate_signature(&cred.token, path, "")?;

            let mut headers = self.create_headers()?;
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

    async fn run(&self, token: &str) -> Result<Vec<SignResult>> {
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
            
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
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

        // 构建完整的 URL
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

    let client = SklandClient::new()?;
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