use crate::error::Error as AliError;

use serde::{de::DeserializeOwned, Deserialize};
use sha1::Sha1;
use hmac::{Hmac, Mac};
use rand::Rng;
use rand::distributions::Alphanumeric;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_xml_rs::from_str;

#[derive(Debug, Clone,Deserialize)]
pub struct Error {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String
}
// 查询返回结果
/*
#[derive(Debug, Clone,Deserialize)]
#[serde(rename_all = "PascalCase")] 
pub struct ListCnameResultCertificate {
    cert_id: String,
    status: String,
    valid_start_date: String,
    valid_end_date: String,
}
#[derive(Debug, Clone,Deserialize)]
#[serde(rename_all = "PascalCase")] 
pub struct ListCnameResultCname {
    domain: String,
    status: String,
    certificate: Option<ListCnameResultCertificate>
}
#[derive(Debug, Clone,Deserialize)]
#[serde(rename_all = "PascalCase")] 
pub struct ListCnameResult {
    bucket: String,
    owner: String,
    cname: Option<ListCnameResultCname>
}
 */
#[derive(Debug, Clone)]
pub struct Client {
    pub access_key_id: String,
    pub access_key_secret: String,
    pub end_point: String,
    pub current_time: String,
    //pub timestamp: String,
    pub version: String,
}
type HmacSha1 = Hmac<Sha1>;
fn generate_random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}
/// 哈希值
pub fn hashed_payload(body:&str) -> String {

    let result = md5::compute(body.as_bytes());

    // Encode the result in Base64
    STANDARD.encode(result.as_ref())

}
/// 计算哈希值
/// 哈希值
pub fn hmac_sha1(key: &[u8], data:&str) -> Vec<u8> {
    //HmacSha256::new_from_slice(key)
    let mut mac = HmacSha1::new_from_slice(key)
            .expect("Invalid key length");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    let code_bytes = result.into_bytes();
    code_bytes[..].to_vec()

}
pub fn hmac_sha256_encode(key: &[u8], data:&str) -> String {
    let result = hmac_sha1(key, data);
    STANDARD.encode(result)
}


impl Client {
    pub fn new(
        access_key_id: String,
        access_key_secret: String,
        end_point: Option<String>,
        version: Option<String>
    ) -> Self {
        let now = chrono::Utc::now();
        let current_time = now.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        //println!("today: {}", current_time);
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
    pub async fn do_request<U: DeserializeOwned >(&self, method:&str, action:&str, query:&str, body:&str,bucket:&str) -> Result<Option<U>,AliError> {
        let client = reqwest::Client::new();
        let end_point = if bucket.is_empty() {
            self.end_point.clone()
        } else {
            bucket.to_string() + "." + &self.end_point
        };
        let full_url = 
        if !query.is_empty() {
            end_point.clone() + "?" + query
        }else{
            end_point.clone()
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
        let authorization = "OSS ".to_string()
         + &self.access_key_id 
         + ":" 
         + &self.str_to_sign(method, action, query, body,bucket,&nonce);
        //println!("authorization: {}", authorization);
        let req_builder = if !body.is_empty() {
            req_builder.body(body.to_string())
        } else {
            req_builder
        };
        let content_type = if !body.is_empty() {"application/x-www-form-urlencoded"} else {"application/json"};
         
        let req_builder = req_builder
            .header("Accept", "application/json")
            .header("Content-Type", content_type)
            .header("Content-MD5", hashed_payload(body))
            .header("Authorization", authorization)
            .header("Date", &self.current_time)
            .header("Host", &end_point)
            .header("x-oss-action",action)
            .header("x-oss-signature-method", "HMAC-SHA1")
            .header("x-oss-signature-nonce", &nonce)
            .header("x-oss-version", &self.version)
            ;
        let res = req_builder.send().await?;
        let status_code = res.status();
        let res_text = res.text().await?;
         println!("res_text: {}", res_text);
        
        if status_code == 200 {
           // let res: U = from_str(&res_text)?;
            if res_text.is_empty(){
                //let result:U = Default::default();
                //return Ok( result);
                return Ok(None);
            }else{
                let res: U = from_str(&res_text)?;
                return Ok(Some(res));
            }

        }else{
            //let code = res["Error"]
            let res: Error = from_str(&res_text)?;
            return Err(AliError::new("do_request".to_string(),format!("code:{}, message: {}",res.code,res.message)));
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
    pub fn canonical_request(&self,method:&str, action:&str, query:&str, body:&str,bucket:&str, nonce: &str) -> String {
        let request_payload_hashed = hashed_payload(body);
        //let action = action.to_string().to_ascii_lowercase();
        let content_type = if !body.is_empty() {"application/x-www-form-urlencoded"} else {"application/json"};
        let query = if !query.is_empty() && !query.starts_with("?") {
            "?".to_string() + query
        } else {
            "".to_string()
        };
        let base_uri = if bucket.is_empty() {
            "/".to_string()
        } else {
            "/".to_string() + bucket + "/"
        };
        let canonical_request = 
                    //HTTPRequestMethod
                    method.to_string() + "\n"
                    // acceept
                    //+ "\n"
                    // content md5
                    + &request_payload_hashed + "\n"
                    + content_type +"\n"
                    //date 
                    + &self.current_time + "\n"
                    //CanonicalHeaders
                    + "x-oss-action:" + &action + "\n"
                    + "x-oss-signature-method:HMAC-SHA1\n"
                    + "x-oss-signature-nonce:" + nonce + "\n"
                    + "x-oss-version:" + &self.version + "\n"
                    // resource
                    + &base_uri + &query
                    ;
        println!("canonical_request: {}\n", canonical_request);
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
    pub fn str_to_sign(&self,method:&str, action:&str, query:&str, body:&str,bucket:&str,nonce: &str) -> String {
        let canonical_request = self.canonical_request(method, action, query, body,bucket,nonce);
         
        let secret_key =  &self.access_key_secret;
        hmac_sha256_encode(secret_key.as_bytes(), &canonical_request) 
    }
    

}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_hmac_equal() {
          
        //assert_eq!(lft,rgt);
    }
}