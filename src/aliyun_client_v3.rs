/// 阿里云客户端基于V3签名构建
/// https://help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature
use std::{borrow::Cow, collections::{BTreeMap, HashMap}};

use crate::{err, utils::errors::Error};

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Sha256, Digest};
use hex;
use hmac::{Hmac, Mac};
use crate::utils::helpers::random_string;
use time::OffsetDateTime;
use time::macros::format_description;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

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
 
/// 哈希值
pub fn hashed_payload(body:&[u8]) -> String {
   
    let mut hasher = Sha256::new();
    hasher.update(body);
    let result = hasher.finalize();
    //let a = result.clone();
    //let o = hex::encode(a);
    //println!("sha256_old:{}", o);
    format!("{:x}", result).to_lowercase()
    //hex::encode(result)
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
// 对指定的字符串进行URL编码。返回值类型为&Str，URLEncoder.encode(str, "UTF-8").replace("+", "%20").replace("*", "%2A").replace("%7E", "~")
pub fn percent_code(encode_str: &str) -> Cow<'_, str> {
    let encoded = utf8_percent_encode(encode_str, NON_ALPHANUMERIC)
        .to_string()
        .replace("+", "20%")
        .replace("%5F", "_")
        .replace("%2D", "-")
        .replace("%2E", ".")
        .replace("%7E", "~");
        
    Cow::Owned(encoded) // 返回一个 Cow<str> 可以持有 String 或 &str
}
/// 构建规范化查询字符串
/// let query_params = vec![
/// ("name", "Alice"),
/// ("age", "30"),
/// ("city", "Beijing")
/// ];

pub fn build_sored_encoded_query_string(query_params: &[(&str, &str)]) -> String {
    // 按参数名升序排序并使用 BTreeMap 处理重复
    let sorted_query_params: BTreeMap<_, _> = query_params.iter().copied().collect();
    
    // URI 编码
    let encoded_params: Vec<String> = sorted_query_params
        .into_iter()
        .map(|(k, v)| {
            let encoded_key = percent_code(k);
            let encoded_value = percent_code(v);
            format!("{}={}", encoded_key, encoded_value)
        })
        .collect();
    
    // 使用 & 连接所有编码后的参数
    encoded_params.join("&")
}
// 定义 FormData 数据类型
#[derive(Debug, Clone)]
pub enum FormValue {
    String(String),
    // 添加类型：Vec<String>, HashSet<String> 或者 HashMap<String, String> 等
    Vec(Vec<String>),
    HashMap(HashMap<String, String>),
}
// 定义一个body请求体枚举，用于统一处理请求体类型,包含Json,Map，二进制类型 
pub enum RequestBody {
    Json(HashMap<String, Value>), // Json
    Binary(Vec<u8>), // Binary
    FormData(HashMap<String, FormValue>), //  FormData 
    None,
}
impl Client {
    /// #Args
    /// * access_key_id: 阿里云access_key_id
    /// * access_key_secret: 阿里云access_key_secret
    /// * end_point: 如 Some("ocr-api.cn-hangzhou")
    /// * version: 如 Some("2018-12-07")
    pub fn new(
        access_key_id: String,
        access_key_secret: String,
        end_point: Option<String>,
        version: Option<String>
    ) -> Self {
        //let now = chrono::Utc::now();
  
        let current_time = OffsetDateTime::now_utc()
        .format(&format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
        ))
        .unwrap(); // 确保格式正确
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
    /// * canonical_uri: 请求路径如： /v1/instances/list ，大部分情况下直接传 / 即可
    /// * query: 请求参数，vec![("key1", "value1"), ("key2", "value2")]
    /// * body: 请求体,支持 json,二进制数据，字符串，表单数据 参见 RequestBody 枚举
    /// # Returns
    /// 请求结果
    pub async fn do_request<U: DeserializeOwned>(&self, method:&str, action:&str,canonical_uri: &str, query:Vec<(&str,&str)>, body: RequestBody) -> Result<U,Error> {
        let client = reqwest::Client::new();
        let query = build_sored_encoded_query_string(&query);
        let full_url = 
        if !query.is_empty() {
           self.end_point.clone().to_string() + "?" + &query
        }else{
           self.end_point.clone().to_string()
        };
        let full_url = "https://".to_string() + canonical_uri+ &full_url;
        let mut req_builder = match method {
            "GET" => client.get(full_url),
            "POST" => client.post(full_url),
            _ => client.get(full_url),
        };
        let nonce = random_string(32);
        let signature:String;
        let content_sha256:String;
        match &body { // 使用引用来避免移动
            RequestBody::Json(body_map) => {
                let body_content = json!(body_map).to_string();
                req_builder = req_builder.header("Content-Type", "application/json");
                req_builder = req_builder.body(body_content.clone());
                let tmp = body_content.as_bytes();
                signature = self.str_to_sign(method, action,canonical_uri, &query, tmp,&nonce);
                content_sha256 = hashed_payload(tmp);
            },  // 若 body 为map，转化为 &str 类型，存储 body_content 变量中
            RequestBody::Binary(body_byes) => {
                req_builder = req_builder.header("Content-Type", "application/octet-stream");
                req_builder = req_builder.body(body_byes.clone().to_vec());
                let tmp = body_byes.as_slice();
                signature = self.str_to_sign(method, action,canonical_uri, &query, tmp,&nonce);
                content_sha256 = hashed_payload(tmp);
                //String::new()
            }, // 若 body 为二进制类型这里可以保留空字符串，body_content 变量为空
            RequestBody::FormData(form_data) => {
                let params: Vec<String> = form_data
                .iter()
                .flat_map(|(k, v)| {
                    match v {
                        FormValue::String(s) => {
                            // 当 FormValue 为 String 时
                            vec![format!("{}={}", percent_code(k), percent_code(&s))]
                        },
                        FormValue::Vec(vec) => {
                            // 当 FormValue 为 Vec 时
                            vec.iter()
                                .map(|s| format!("{}={}", percent_code(k), percent_code(s)))
                                .collect::<Vec<_>>()
                        },
                        FormValue::HashMap(map) => {
                            // 当 FormValue 为 HashMap 时
                            map.iter()
                                .map(|(sk, sv)| format!("{}={}", percent_code(sk), percent_code(sv)))
                                .collect::<Vec<_>>()
                        },
                    }
                })
                .collect();
                let body_content = params.join("&"); //  组成 key=value&key=value 的形式
                if !body_content.is_empty() { 
                    req_builder = req_builder.header("Content-Type", "application/x-www-form-urlencoded");
                    req_builder = req_builder.body(body_content.clone());
                    
                }
                let tmp = body_content.as_bytes();
                signature = self.str_to_sign(method, action, canonical_uri,&query, tmp,&nonce);
                content_sha256 = hashed_payload(tmp);
            },
            RequestBody::None =>{
                let body_content = String::new();
                let tmp = body_content.as_bytes();
                signature = self.str_to_sign(method, action, canonical_uri,&query, tmp,&nonce);
                content_sha256 = hashed_payload(tmp);
            },
        };

       // println!("signature:{}", signature);
        let authorization = "ACS3-HMAC-SHA256 Credential=".to_string()
         + &self.access_key_id 
         + ",SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version, Signature=" 
         + &signature;
        //println!("authorization: {}", authorization);

        //let content_type = if method == "POST" {"application/x-www-form-urlencoded"} else {"application/json"};
         
        let req_builder = req_builder
            //.header("Content-Type", "application/json; charset=utf-8")
            //.header("Content-Type", content_type)
            .header("Authorization", authorization)
            .header("Host", &self.end_point)
            .header("x-acs-action",action)
            .header("x-acs-content-sha256", content_sha256)
            .header("x-acs-date", &self.current_time)
            .header("x-acs-signature-nonce", &nonce)
            .header("x-acs-version", &self.version)
            ;
        let res = req_builder.send().await?;
        let status_code = res.status();
        let res_text = res.text().await?;
      // println!("res_text: {}", res_text);
        if status_code == 200 {
            let res: U = serde_json::from_str(&res_text)?;
            
            return Ok(res);
        }else{
            return err!("请求失败");
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
    pub fn canonical_request(&self,method:&str, action:&str, canonical_uri: &str,query:&str, body: &[u8], nonce: &str) -> String {
        let request_payload_hashed = hashed_payload(body);
        
        let canonical_request = 
                    //HTTPRequestMethod
                    method.to_string() + "\n"
                    //CanonicalURI
                    + canonical_uri+"\n"
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
                    + "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version\n"
                     
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
    pub fn str_to_sign(&self,method:&str, action:&str,canonical_uri:&str, query:&str, body: &[u8],nonce: &str) -> String {
        let canonical_request = self.canonical_request(method, action,canonical_uri, query, body,nonce);
        //println!("canonical_request: {}", canonical_request);
        // to &[u8]
        //let canonical_request_bytes = canonical_request.as_bytes();
        let algorithm = "ACS3-HMAC-SHA256".to_string();
        let sign_str = 
            algorithm + "\n"
            + &hashed_payload(canonical_request.as_bytes())
            ;
        let secret_key =  &self.access_key_secret;
        hmac_sha256_hex(secret_key.as_bytes(), &sign_str) 
    }
    

}
#[cfg(test)]
mod test {
    use crate::utils::app_env;
    use time::OffsetDateTime;
    use super::*;

    #[test]
    fn test_time() {
        let current_time = OffsetDateTime::now_utc()
        .format(&format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .unwrap(); // 确保格式正确
        println!("{}", current_time);
    }
    #[tokio::test]
    async fn test_ocr() -> Result<(), Error>  {
        let app_env = app_env::AppEnv::get_env();

        let client = Client::new(app_env.ocr_access_secret_id, app_env.ocr_access_secret_key,Some("ocr-api.cn-hangzhou".to_string()),Some("2021-07-07".to_string()));
        let idcard_path = "/mnt/e/work/tmp/idcard_a.jpg";
        // read file to bytes
        let bytes = std::fs::read(idcard_path).unwrap();
        let result = client.do_request::<serde_json::Value>("POST", "RecognizeIdcard","/", vec![], RequestBody::Binary(bytes)).await?;
        println!("{:?}", result);
        Ok(())
   }
}