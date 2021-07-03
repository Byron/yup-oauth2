//! This module provides a token source (`GetToken`) that obtains tokens using user credentials
//! for use by software (i.e., non-human actors) to get access to Google services.
//!
//! Resources:
//! - [gcloud auth application-default login](https://cloud.google.com/sdk/gcloud/reference/auth/application-default/login)
//!
use crate::error::Error;
use crate::types::TokenInfo;
use hyper::header;
use serde::{Deserialize, Serialize};
use std::io;
use url::form_urlencoded;

const TOKEN_URI: &'static str = "https://accounts.google.com/o/oauth2/token";

/// JSON schema of authorized user secret. You can obtain it by
/// running on the client: `gcloud auth application-default login`.
///
/// You can use `helpers::read_authorized_user_secret()` to read a JSON file
/// into a `AuthorizedUserSecret`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorizedUserSecret {
    /// client_id
    pub client_id: String,
    /// client_secret
    pub client_secret: String,
    /// refresh_token
    pub refresh_token: String,
    #[serde(rename = "type")]
    /// key_type
    pub key_type: String,
}

pub struct AuthorizedUserFlowOpts {
    pub(crate) secret: AuthorizedUserSecret,
}

/// AuthorizedUserFlow can fetch oauth tokens using an authorized user secret.
pub struct AuthorizedUserFlow {
    secret: AuthorizedUserSecret,
}

impl AuthorizedUserFlow {
    pub(crate) fn new(opts: AuthorizedUserFlowOpts) -> Result<Self, io::Error> {
        Ok(AuthorizedUserFlow {
            secret: opts.secret,
        })
    }

    /// Send a request for a new Bearer token to the OAuth provider.
    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper::Client<C>,
        _scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    {
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", self.secret.client_id.as_str()),
                ("client_secret", self.secret.client_secret.as_str()),
                ("refresh_token", self.secret.refresh_token.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .finish();

        let request = hyper::Request::post(TOKEN_URI)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap();

        log::debug!("requesting token from authorized user: {:?}", request);
        let (head, body) = hyper_client.request(request).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;
        log::debug!("received response; head: {:?}, body: {:?}", head, body);
        TokenInfo::from_json(&body)
    }
}
