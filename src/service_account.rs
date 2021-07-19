//! This module provides a flow that obtains tokens for service accounts.
//!
//! Service accounts are usually used by software (i.e., non-human actors) to get access to
//! resources. Currently, this module only works with RS256 JWTs, which makes it at least suitable
//! for authentication with Google services.
//!
//! Resources:
//! - [Using OAuth 2.0 for Server to Server
//! Applications](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
//! - [JSON Web Tokens](https://jwt.io/)
//!
//! Copyright (c) 2016 Google Inc (lewinb@google.com).

use crate::error::Error;
use crate::types::TokenInfo;

use std::io;

use hyper::header;
use rustls::{
    self,
    internal::pemfile,
    sign::{self, SigningKey},
    PrivateKey,
};
use serde::{Deserialize, Serialize};
use url::form_urlencoded;

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const GOOGLE_RS256_HEAD: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

/// Encodes s as Base64
fn append_base64<T: AsRef<[u8]> + ?Sized>(s: &T, out: &mut String) {
    base64::encode_config_buf(s, base64::URL_SAFE, out)
}

/// Decode a PKCS8 formatted RSA key.
fn decode_rsa_key(pem_pkcs8: &str) -> Result<PrivateKey, io::Error> {
    let private_keys = pemfile::pkcs8_private_keys(&mut pem_pkcs8.as_bytes());

    match private_keys {
        Ok(mut keys) if !keys.is_empty() => {
            keys.truncate(1);
            Ok(keys.remove(0))
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Not enough private keys in PEM",
        )),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Error reading key from PEM",
        )),
    }
}

/// JSON schema of secret service account key.
///
/// You can obtain the key from the [Cloud Console](https://console.cloud.google.com/).
///
/// You can use `helpers::read_service_account_key()` as a quick way to read a JSON client
/// secret into a ServiceAccountKey.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServiceAccountKey {
    #[serde(rename = "type")]
    /// key_type
    pub key_type: Option<String>,
    /// project_id
    pub project_id: Option<String>,
    /// private_key_id
    pub private_key_id: Option<String>,
    /// private_key
    pub private_key: String,
    /// client_email
    pub client_email: String,
    /// client_id
    pub client_id: Option<String>,
    /// auth_uri
    pub auth_uri: Option<String>,
    /// token_uri
    pub token_uri: String,
    /// auth_provider_x509_cert_url
    pub auth_provider_x509_cert_url: Option<String>,
    /// client_x509_cert_url
    pub client_x509_cert_url: Option<String>,
}

/// Permissions requested for a JWT.
/// See https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests.
#[derive(Serialize, Debug)]
struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    #[serde(rename = "sub")]
    subject: Option<&'a str>,
    scope: String,
}

impl<'a> Claims<'a> {
    fn new<T>(key: &'a ServiceAccountKey, scopes: &[T], subject: Option<&'a str>) -> Self
    where
        T: AsRef<str>,
    {
        let iat = chrono::Utc::now().timestamp();
        let expiry = iat + 3600 - 5; // Max validity is 1h.

        let scope = crate::helper::join(scopes, " ");
        Claims {
            iss: &key.client_email,
            aud: &key.token_uri,
            exp: expiry,
            iat,
            subject,
            scope,
        }
    }
}

/// A JSON Web Token ready for signing.
pub(crate) struct JWTSigner {
    signer: Box<dyn rustls::sign::Signer>,
}

impl JWTSigner {
    fn new(private_key: &str) -> Result<Self, io::Error> {
        let key = decode_rsa_key(private_key)?;
        let signing_key = sign::RSASigningKey::new(&key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Couldn't initialize signer"))?;
        let signer = signing_key
            .choose_scheme(&[rustls::SignatureScheme::RSA_PKCS1_SHA256])
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "Couldn't choose signing scheme")
            })?;
        Ok(JWTSigner { signer })
    }

    fn sign_claims(&self, claims: &Claims) -> Result<String, rustls::TLSError> {
        let mut jwt_head = Self::encode_claims(claims);
        let signature = self.signer.sign(jwt_head.as_bytes())?;
        jwt_head.push_str(".");
        append_base64(&signature, &mut jwt_head);
        Ok(jwt_head)
    }

    /// Encodes the first two parts (header and claims) to base64 and assembles them into a form
    /// ready to be signed.
    fn encode_claims(claims: &Claims) -> String {
        let mut head = String::new();
        append_base64(GOOGLE_RS256_HEAD, &mut head);
        head.push_str(".");
        append_base64(&serde_json::to_string(&claims).unwrap(), &mut head);
        head
    }
}

pub struct ServiceAccountFlowOpts {
    pub(crate) key: ServiceAccountKey,
    pub(crate) subject: Option<String>,
}

/// ServiceAccountFlow can fetch oauth tokens using a service account.
pub struct ServiceAccountFlow {
    key: ServiceAccountKey,
    subject: Option<String>,
    signer: JWTSigner,
}

impl ServiceAccountFlow {
    pub(crate) fn new(opts: ServiceAccountFlowOpts) -> Result<Self, io::Error> {
        let signer = JWTSigner::new(&opts.key.private_key)?;
        Ok(ServiceAccountFlow {
            key: opts.key,
            subject: opts.subject,
            signer,
        })
    }

    /// Send a request for a new Bearer token to the OAuth provider.
    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper::Client<C>,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    {
        let claims = Claims::new(&self.key, scopes, self.subject.as_ref().map(|x| x.as_str()));
        let signed = self.signer.sign_claims(&claims).map_err(|_| {
            Error::LowLevelError(io::Error::new(
                io::ErrorKind::Other,
                "unable to sign claims",
            ))
        })?;
        let rqbody = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", signed.as_str())])
            .finish();
        let request = hyper::Request::post(&self.key.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(rqbody))
            .unwrap();
        log::debug!("requesting token from service account: {:?}", request);
        let (head, body) = hyper_client.request(request).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;
        log::debug!("received response; head: {:?}, body: {:?}", head, body);
        TokenInfo::from_json(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper::read_service_account_key;

    // Valid but deactivated key.
    const TEST_PRIVATE_KEY_PATH: &'static str = "examples/Sanguine-69411a0c0eea.json";

    // Uncomment this test to verify that we can successfully obtain tokens.
    // #[tokio::test]
    #[allow(dead_code)]
    async fn test_service_account_e2e() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let acc = ServiceAccountFlow::new(ServiceAccountFlowOpts { key, subject: None }).unwrap();
        let client =
            hyper::Client::builder().build(hyper_rustls::HttpsConnector::with_native_roots());
        println!(
            "{:?}",
            acc.token(&client, &["https://www.googleapis.com/auth/pubsub"])
                .await
        );
        println!(
            "{:?}",
            acc.token(
                &client,
                &["https://some.scope/likely-to-hand-out-id-tokens"]
            )
            .await
        );
    }

    #[tokio::test]
    async fn test_jwt_initialize_claims() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let claims = Claims::new(&key, &scopes, None);

        assert_eq!(
            claims.iss,
            "oauth2-public-test@sanguine-rhythm-105020.iam.gserviceaccount.com".to_string()
        );
        assert_eq!(claims.scope, "scope1 scope2 scope3".to_string());
        assert_eq!(
            claims.aud,
            "https://accounts.google.com/o/oauth2/token".to_string()
        );
        assert!(claims.exp > 1000000000);
        assert!(claims.iat < claims.exp);
        assert_eq!(claims.exp - claims.iat, 3595);
    }

    #[tokio::test]
    async fn test_jwt_sign() {
        let key = read_service_account_key(TEST_PRIVATE_KEY_PATH)
            .await
            .unwrap();
        let scopes = vec!["scope1", "scope2", "scope3"];
        let signer = JWTSigner::new(&key.private_key).unwrap();
        let claims = Claims::new(&key, &scopes, None);
        let signature = signer.sign_claims(&claims);

        assert!(signature.is_ok());

        let signature = signature.unwrap();
        assert_eq!(
            signature.split(".").nth(0).unwrap(),
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
        );
    }
}
