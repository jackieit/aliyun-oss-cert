use aliyun_client_v2::Client;
use argh::FromArgs;
mod aliyun_client_v2;
mod error;

#[derive(Debug, serde::Deserialize)]
struct EmptyResult;

#[derive(Debug, FromArgs)]
/// Reach new heights.
struct CommonArgs {
    /// domain name
    #[argh(positional)]
    domain: String,
    /// endpoint name
    #[argh(option)]
    endpoint: Option<String>,
    /// bucket name
    #[argh(positional)]
    bucket: String,
    /// cert file path example ./apiv2.crt
    #[argh(positional)]
    cert_path: String,

    /// key file path example ./apiv2.key
    #[argh(positional)]
    key_path: String,

    /// oss access key id
    #[argh(positional)]
    access_key_id: String,

    /// oss access key secret
    #[argh(positional)]
    access_key_secret: String,
}
#[tokio::main]
async fn main() {
    let args: CommonArgs = argh::from_env();
    //println!("Hello, world! {:?}", args);
    let client = Client::new(
        args.access_key_id,
        args.access_key_secret,
        args.endpoint,
        None,
    );
    let pub_key = std::fs::read_to_string(args.cert_path).expect("Read public key file failed");
    let pri_key = std::fs::read_to_string(args.key_path).expect("Read private key file failed");
    let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_string()
    + "<BucketCnameConfiguration>"
    + "<Cname>"
    + "<Domain>"+ &args.domain + "</Domain>"
    + "<CertificateConfiguration>"
   // + "<CertId>"+&cert_id+"</CertId>"
    + "<Certificate>"
    + &pub_key
    + "</Certificate>"
    + "<PrivateKey>"
    + &pri_key
    + "</PrivateKey>";

    // let body = if let Some(prev_cert_id) = prev_cert_id {
    //     body+"<PreviousCertId>"+&prev_cert_id+"</PreviousCertId>"
    // }else{
    //     "".to_string()
    // };

    let body = body + "<Force>true</Force>";
    //+ "<DeleteCertificate>true</DeleteCertificate>"
    let body = body + "</CertificateConfiguration>" + "</Cname>" + "</BucketCnameConfiguration>";
    //println!("body: {:?}", body);
    let res = client
        .do_request::<EmptyResult>("POST", "PutCname", "cname&comp=add", &body, &args.bucket)
        .await;
    match res {
        Ok(res) => {
            if res.is_none() {
                println!("Update cert success!");
            }
        }
        Err(err) => {
            println!(" {:?}", err);
        }
    }
}
