//! Module containing types related to delegates.
use crate::error::{AuthErrorOr, Error};

use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use std::future::Future;

/// Contains state of pending authentication requests
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceAuthResponse {
    /// The device verification code.
    pub device_code: String,
    /// Code the user must enter ...
    pub user_code: String,
    /// ... at the verification URI
    pub verification_uri: String,
    /// The `user_code` expires at the given time
    /// It's the time the user has left to authenticate your application
    pub expires_at: DateTime<Utc>,
    /// The interval in which we may poll for a status change
    /// The server responds with errors of we poll too fast.
    pub interval: Duration,
}

impl DeviceAuthResponse {
    pub(crate) fn from_json(json_data: &[u8]) -> Result<Self, Error> {
        Ok(serde_json::from_slice::<AuthErrorOr<_>>(json_data)?.into_result()?)
    }
}

impl<'de> serde::Deserialize<'de> for DeviceAuthResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct RawDeviceAuthResponse {
            device_code: String,
            user_code: String,
            // The standard dictates that verification_uri is required, but
            // sadly google uses verification_url currently. One of these two
            // fields need to be set and verification_uri takes precedence if
            // they both are set.
            verification_uri: Option<String>,
            verification_url: Option<String>,
            expires_in: i64,
            interval: Option<u64>,
        }

        let RawDeviceAuthResponse {
            device_code,
            user_code,
            verification_uri,
            verification_url,
            expires_in,
            interval,
        } = RawDeviceAuthResponse::deserialize(deserializer)?;

        let verification_uri = verification_uri.or(verification_url).ok_or_else(|| {
            serde::de::Error::custom("neither verification_uri nor verification_url specified")
        })?;
        let expires_at = Utc::now() + chrono::Duration::seconds(expires_in);
        let interval = Duration::from_secs(interval.unwrap_or(5));
        Ok(DeviceAuthResponse {
            device_code,
            user_code,
            verification_uri,
            expires_at,
            interval,
        })
    }
}

/// DeviceFlowDelegate methods are called when a device flow needs to ask the
/// application what to do in certain cases.
pub trait DeviceFlowDelegate: Send + Sync {
    /// The server has returned a `user_code` which must be shown to the user,
    /// along with the `verification_uri`.
    /// # Notes
    /// * Will be called exactly once, provided we didn't abort during `request_code` phase.
    fn present_user_code<'a>(
        &'a self,
        device_auth_resp: &'a DeviceAuthResponse,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(present_user_code(device_auth_resp))
    }

    // The name of the device code
    // fn device_code_name(&self) -> &str {
    //     "code"
    // }

    // The URL for the Grant Type Check
    // fn grant_type_for_check(&self) -> &str {
    //     //"http://oauth.net/grant_type/device/1.0"
    //     crate::device::GOOGLE_GRANT_TYPE
    // }
}

async fn present_user_code(device_auth_resp: &DeviceAuthResponse) {
    println!(
        "Please enter {} at {} and grant access to this application",
        device_auth_resp.user_code, device_auth_resp.verification_uri
    );
    println!("Do not close this application until you either denied or granted access.");
    println!(
        "You have time until : {}.",
        device_auth_resp.expires_at.with_timezone(&Local)
    );
}

/// InstalledFlowDelegate methods are called when an installed flow needs to ask
/// the application what to do in certain cases.
pub trait InstalledFlowDelegate: Send + Sync {
    /// Configure a custom redirect uri if needed.
    fn redirect_uri(&self) -> Option<&str> {
        None
    }

    /// We need the user to navigate to a URL using their browser and potentially paste back a code
    /// (or maybe not). Whether they have to enter a code depends on the InstalledFlowReturnMethod
    /// used.
    fn present_user_url<'a>(
        &'a self,
        url: &'a str,
        need_code: bool,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(present_user_url(url, need_code))
    }
}

async fn present_user_url(url: &str, need_code: bool) -> Result<String, String> {
    use tokio::io::AsyncBufReadExt;
    if need_code {
        println!(
            "Please direct your browser to {}, follow the instructions and enter the \
             code displayed here: ",
            url
        );
        let mut user_input = String::new();
        tokio::io::BufReader::new(tokio::io::stdin())
            .read_line(&mut user_input)
            .await
            .map_err(|e| format!("couldn't read code: {}", e))?;
        // remove trailing whitespace.
        user_input.truncate(user_input.trim_end().len());
        Ok(user_input)
    } else {
        println!(
            "Please direct your browser to {} and follow the instructions displayed \
             there.",
            url
        );
        Ok(String::new())
    }
}

/// Uses all default implementations in the DeviceFlowDelegate trait.
#[derive(Copy, Clone)]
pub struct DefaultDeviceFlowDelegate;
impl DeviceFlowDelegate for DefaultDeviceFlowDelegate {}

/// Uses all default implementations in the DeviceFlowDelegate trait.
#[derive(Copy, Clone)]
pub struct DefaultInstalledFlowDelegate;
impl InstalledFlowDelegate for DefaultInstalledFlowDelegate {}