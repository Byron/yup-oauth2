use crate::error::Error;
use crate::types::TokenInfo;

pub struct ApplicationDefaultCredentialsFlowOpts;

/// ServiceAccountFlow can fetch oauth tokens using a service account.
pub struct ApplicationDefaultCredentialsFlow;
impl ApplicationDefaultCredentialsFlow {
    pub(crate) fn new(_opts: ApplicationDefaultCredentialsFlowOpts) -> Self {
        ApplicationDefaultCredentialsFlow {}
    }

    pub(crate) async fn token<C, T>(
        &self,
        hyper_client: &hyper::Client<C>,
        scopes: &[T],
    ) -> Result<TokenInfo, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    {
        let scope = crate::helper::join(scopes, ",");
        let token_uri = format!("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes={}", scope);
        let request = hyper::Request::get(token_uri)
            .header("Metadata-Flavor", "Google")
            .body(hyper::Body::from(String::new())) // why body is needed?
            .unwrap();
        log::debug!("requesting token from metadata server: {:?}", request);
        let (head, body) = hyper_client.request(request).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;
        log::debug!("received response; head: {:?}, body: {:?}", head, body);
        TokenInfo::from_json(&body)
    }
}

// eof
