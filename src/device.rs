use crate::authenticator_delegate::{
    DefaultDeviceFlowDelegate, DeviceAuthResponse, DeviceFlowDelegate,
};
use crate::error::{AuthError, Error};
use crate::types::{ApplicationSecret, TokenInfo};

use std::borrow::Cow;
use std::time::Duration;

use hyper::header;
use url::form_urlencoded;

pub const GOOGLE_DEVICE_CODE_URL: &str = "https://accounts.google.com/o/oauth2/device/code";

// https://developers.google.com/identity/protocols/OAuth2ForDevices#step-4:-poll-googles-authorization-server
pub const GOOGLE_GRANT_TYPE: &str = "http://oauth.net/grant_type/device/1.0";

/// Implements the [Oauth2 Device Flow](https://developers.google.com/youtube/v3/guides/authentication#devices)
/// It operates in two steps:
/// * obtain a code to show to the user
/// * (repeatedly) poll for the user to authenticate your application
pub struct DeviceFlow {
    pub(crate) app_secret: ApplicationSecret,
    pub(crate) device_code_url: Cow<'static, str>,
    pub(crate) flow_delegate: Box<dyn DeviceFlowDelegate>,
    pub(crate) grant_type: Cow<'static, str>,
}

impl DeviceFlow {
    /// Create a new DeviceFlow. The default FlowDelegate will be used and the
    /// default wait time is 120 seconds.
    pub(crate) fn new(app_secret: ApplicationSecret) -> Self {
        DeviceFlow {
            app_secret,
            device_code_url: GOOGLE_DEVICE_CODE_URL.into(),
            flow_delegate: Box::new(DefaultDeviceFlowDelegate),
            grant_type: GOOGLE_GRANT_TYPE.into(),
        }
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
        let device_auth_resp = Self::request_code(
            &self.app_secret,
            hyper_client,
            &self.device_code_url,
            scopes,
        )
        .await?;
        log::debug!("Presenting code to user");
        self.flow_delegate
            .present_user_code(&device_auth_resp)
            .await;
        self.wait_for_device_token(
            hyper_client,
            &self.app_secret,
            &device_auth_resp,
            &self.grant_type,
        )
        .await
    }

    async fn wait_for_device_token<C>(
        &self,
        hyper_client: &hyper::Client<C>,
        app_secret: &ApplicationSecret,
        device_auth_resp: &DeviceAuthResponse,
        grant_type: &str,
    ) -> Result<TokenInfo, Error>
    where
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    {
        let mut interval = device_auth_resp.interval;
        log::debug!("Polling every {:?} for device token", interval);
        loop {
            tokio::time::sleep(interval).await;
            interval = match Self::poll_token(
                &app_secret,
                hyper_client,
                &device_auth_resp.device_code,
                grant_type,
            )
            .await
            {
                Ok(token) => return Ok(token),
                Err(Error::AuthError(AuthError { error, .. }))
                    if error.as_str() == "authorization_pending" =>
                {
                    log::debug!("still waiting on authorization from the server");
                    interval
                }
                Err(Error::AuthError(AuthError { error, .. })) if error.as_str() == "slow_down" => {
                    let interval = interval + Duration::from_secs(5);
                    log::debug!(
                        "server requested slow_down. Increasing polling interval to {:?}",
                        interval
                    );
                    interval
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// The first step involves asking the server for a code that the user
    /// can type into a field at a specified URL. It is called only once, assuming
    /// there was no connection error. Otherwise, it may be called again until
    /// you receive an `Ok` result.
    /// # Arguments
    /// * `client_id` & `client_secret` - as obtained when [registering your application](https://developers.google.com/youtube/registering_an_application)
    /// * `scopes` - an iterator yielding String-like objects which are URLs defining what your
    ///              application is able to do. It is considered good behaviour to authenticate
    ///              only once, with all scopes you will ever require.
    ///              However, you can also manage multiple tokens for different scopes, if your
    ///              application is providing distinct read-only and write modes.
    /// # Panics
    /// * If called after a successful result was returned at least once.
    /// # Examples
    /// See test-cases in source code for a more complete example.
    async fn request_code<C, T>(
        application_secret: &ApplicationSecret,
        client: &hyper::Client<C>,
        device_code_url: &str,
        scopes: &[T],
    ) -> Result<DeviceAuthResponse, Error>
    where
        T: AsRef<str>,
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    {
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", application_secret.client_id.as_str()),
                ("scope", crate::helper::join(scopes, " ").as_str()),
            ])
            .finish();

        // note: works around bug in rustlang
        // https://github.com/rust-lang/rust/issues/22252
        let req = hyper::Request::post(device_code_url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap();
        log::debug!("requesting code from server: {:?}", req);
        let (head, body) = client.request(req).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;
        log::debug!("received response; head: {:?}, body: {:?}", head, body);
        DeviceAuthResponse::from_json(&body)
    }

    /// If the first call is successful, this method may be called.
    /// As long as we are waiting for authentication, it will return `Ok(None)`.
    /// You should call it within the interval given the previously returned
    /// `DeviceAuthResponse.interval` field.
    ///
    /// The operation was successful once you receive an Ok(Some(Token)) for the first time.
    /// Subsequent calls will return the previous result, which may also be an error state.
    ///
    /// Do not call after `PollError::Expired|PollError::AccessDenied` was among the
    /// `Err(PollError)` variants as the flow will not do anything anymore.
    /// Thus in any unsuccessful case which is not `PollError::HttpError`, you will have to start
    /// over the entire flow, which requires a new instance of this type.
    ///
    /// > ⚠️ **Warning**: We assume the caller doesn't call faster than `interval` and are not
    /// > protected against this kind of mis-use.
    ///
    /// # Examples
    /// See test-cases in source code for a more complete example.
    async fn poll_token<'a, C>(
        application_secret: &ApplicationSecret,
        client: &hyper::Client<C>,
        device_code: &str,
        grant_type: &str,
    ) -> Result<TokenInfo, Error>
    where
        C: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
    {
        // We should be ready for a new request
        let req = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[
                ("client_id", application_secret.client_id.as_str()),
                ("client_secret", application_secret.client_secret.as_str()),
                ("device_code", device_code),
                ("grant_type", grant_type),
            ])
            .finish();

        let request = hyper::Request::post(&application_secret.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(req))
            .unwrap(); // TODO: Error checking
        log::debug!("polling for token: {:?}", request);
        let (head, body) = client.request(request).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;
        log::debug!("received response; head: {:?} body: {:?}", head, body);
        TokenInfo::from_json(&body)
    }
}