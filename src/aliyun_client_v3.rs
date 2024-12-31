use crate::error::Error;

use serde::de::DeserializeOwned;
use sha2::{Sha256, Digest};
use hex;
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::distributions::Alphanumeric;

#[derive(Debug, Clone)]
pub struct Client {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub end_point: String,
    pub current_time: String,
    //pub timestamp: String,
    pub version: String,
}
type HmacSha256 = Hmac<Sha256>;
fn generate_random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
/// 哈希值
pub fn hashed_payload(body:&str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let result = hasher.finalize();
    hex::encode(result)
}
/// 计算哈希值
/// 哈希值
pub fn hmac_sha256(key: &[u8], data:&str) -> Vec<u8> {
    //HmacSha256::new_from_slice(key)
    let mut mac = HmacSha256::new_from_slice(key)
            .expect("Invalid key length");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    code_bytes[..].to_vec()

}
pub fn hmac_sha256_hex(key: &[u8], data:&str) -> String {
    let result = hmac_sha256(key, data);
    hex::encode(result)
}


impl Client {
    pub fn new(
        access_key_id: String,
        access_key_secret: String,
        end_point: Option<String>,
        version: Option<String>
    ) -> Self {
        let now = chrono::Utc::now();
        let current_time = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();;
        //println!("today: {}", today);
        //let timestamp = now.timestamp().to_string(); oss-cn-beijing.aliyuncs.com
        let end_point = end_point.unwrap_or("oss-cn-beijing".to_string());
        let end_point = format!("{}.aliyuncs.com", end_point); 
        let version = version.unwrap_or("2019-05-17".to_string());
        Client {
            access_key_id,
            access_key_secret,
            end_point,
            current_time,
           // timestamp,
            version
        }
    }
    /// 发送请求
    /// # Args
    /// * method: 请求方法，如 GET POST PUT DELETE 等
    /// * action: 请求动作，如 DescribeInstances
    /// * query: 请求参数，如 domain=example.com&record_type=A&record_line=默认
    /// * body: 请求体，如 {"domain":"example.com","record_type":"A","record_line":"默认"}
    /// # Returns
    /// 请求结果
    pub async fn do_request<U: DeserializeOwned>(&self, method:&str, action:&str, query:&str, body:&str) -> Result<U,Error> {
        let client = reqwest::Client::new();
        let full_url = 
        if !query.is_empty() {
           self.end_point.clone().to_string() + "?" + query
        }else{
           self.end_point.clone().to_string()
        };
        let full_url = "https://".to_string() + &full_url;
        let req_builder = match method {
            "GET" => client.get(full_url),
            "POST" => client.post(full_url),
            //"PUT" => client.put(full_url),
            //"DELETE" => client.delete(full_url),
            _ => client.get(full_url),
        };
        let nonce = generate_random_string(32);
        let authorization = "ACS3-HMAC-SHA256 Credential=".to_string()
         + &self.access_key_id 
         + ",SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version, Signature=" 
         + &self.str_to_sign(method, action, query, body,&nonce);
        //println!("authorization: {}", authorization);
        let req_builder = if !body.is_empty() {
            req_builder.body(body.to_string())
        } else {
            req_builder
        };
        let content_type = if method == "POST" {"application/x-www-form-urlencoded"} else {"application/json"};
         
        let req_builder = req_builder
            //.header("Content-Type", "application/json; charset=utf-8")
            .header("Content-Type", content_type)
            .header("Authorization", authorization)
            .header("Host", &self.end_point)
            .header("x-acs-action",action)
            .header("x-acs-content-sha256", hashed_payload(body))
            .header("x-acs-date", &self.current_time)
            .header("x-acs-signature-nonce", &nonce)
            .header("x-acs-version", &self.version)
            ;
        let res = req_builder.send().await?;
        let status_code = res.status();
        let res_text = res.text().await?;
       println!("res_text: {}", res_text);
        if status_code == 200 {
            let res: U = serde_json::from_str(&res_text)?;
            
            return Ok(res);
        }else{
            return Err(Error::new("do_request".to_string(),status_code.to_string()));
        }
    }
    /// 签名字符串拼接
    /// https://www.dnspod.cn/docs/records.html#sign
    /// # Args
    /// * method: 请求方法，如 GET POST PUT DELETE 等
    /// * action: 请求动作，如 DescribeInstances
    /// * query: 请求参数，如 domain=example.com&record_type=A&record_line=默认
    /// * body: 请求体，如 {"domain":"example.com","record_type":"A","record_line":"默认"}
    /// # Returns
    /// 签名字符串
    pub fn canonical_request(&self,method:&str, action:&str, query:&str, body:&str, nonce: &str) -> String {
        let request_payload_hashed = hashed_payload(body);
        //let action = action.to_string().to_ascii_lowercase();
        //let content_type = if method == "GET" {"application/x-www-form-urlencoded"} else {"application/json"};
        let canonical_request = 
                    //HTTPRequestMethod
                    method.to_string() + "\n"
                    //CanonicalURI
                    + "/\n"
                    //CanonicalQueryString
                    + query + "\n"
                    //CanonicalHeaders
                    //+ "content-type:"+ content_type +"\n"
                    + "host:"+&self.end_point+"\n"
                    + "x-acs-action:" + &action + "\n"
                    + "x-acs-content-sha256:" + &request_payload_hashed+ "\n"
                    + "x-acs-date:" + &self.current_time + "\n"
                    + "x-acs-signature-nonce:" + nonce + "\n"
                    + "x-acs-version:" + &self.version + "\n"
                    + "\n"
                    //SignedHeaders
                    + "host;x-acs-action;x-acs-content-sha256;x-acs-date:x-acs-signature-nonce;x-acs-version\n"
                     
                    + &request_payload_hashed
                    ;
        //let sign_str = sign_str + query + "\n";
        canonical_request
    }
    /// 计算签名字符串
    /// # Args
    /// * method: 请求方法，如 GET POST PUT DELETE 等
    /// * action: 请求动作，如 DescribeInstances
    /// * query: 请求参数，如 domain=example.com&record_type=A&record_line=默认
    /// * body: 请求体，如 {"domain":"example.com","record_type":"A","record_line":"默认"}
    /// # Returns
    /// 签名字符串
    pub fn str_to_sign(&self,method:&str, action:&str, query:&str, body:&str,nonce: &str) -> String {
        let canonical_request = self.canonical_request(method, action, query, body,nonce);
        let algorithm = "ACS3-HMAC-SHA256".to_string();
        let sign_str = 
            algorithm + "\n"
            + &hashed_payload(&canonical_request)
            ;
        let secret_key =  &self.access_key_secret;
        hmac_sha256_hex(secret_key.as_bytes(), &sign_str) 
    }
    

}
