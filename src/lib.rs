//! This library can be used to acquire oauth2.0 authentication for services.
//!
//! For your application to use this library, you will have to obtain an application
//! id and secret by
//! [following this guide](https://developers.google.com/youtube/registering_an_application) (for
//! Google services) respectively the documentation of the API provider you want to connect to.
//!
//! # Device Flow Usage
//! With an application secret you can get started right away, building a `DeviceFlowAuthenticator`
//! and obtaining tokens from it.
//!
//! # Service account "flow"
//! When using service account credentials, no user interaction is required. The access token
//! can be obtained automatically using the private key of the client (which you can download
//! from the API provider). See `examples/service_account/` for an example on how to use service
//! account credentials. See
//! [developers.google.com](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
//! for a detailed description of the protocol. This crate implements OAuth for Service Accounts
//! based on the Google APIs; it may or may not work with other providers.
//!
//! # Installed Flow Usage
//! The installed flow involves showing a URL to the user (or opening it in a browser)
//! and then either prompting the user to enter a displayed code, or make the authorizing
//! website redirect to a web server spun up by this library and running on localhost.
//!
//! In order to use the interactive method, use the `Interactive` `InstalledFlowReturnMethod`;
//! for the redirect method, use `HTTPRedirect`.
//!
//! You can implement your own `AuthenticatorDelegate` in order to customize the flow;
//! the installed flow uses the `present_user_url` method.
//!
//! The returned `Token` will be stored in memory in order to authorize future
//! API requests to the same scopes. The tokens can optionally be persisted to
//! disk by using `persist_tokens_to_disk` when creating the authenticator.
//!
//! The following example, which is derived from the (actual and runnable) example in
//! `examples/test-installed/`, shows the basics of using this crate:
//!
//! ```test_harness,no_run
//! use yup_oauth2::{InstalledFlowAuthenticator, InstalledFlowReturnMethod};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Read application secret from a file. Sometimes it's easier to compile it directly into
//!     // the binary. The clientsecret file contains JSON like `{"installed":{"client_id": ... }}`
//!     let secret = yup_oauth2::read_application_secret("clientsecret.json")
//!         .await
//!         .expect("clientsecret.json");
//!
//!     // Create an authenticator that uses an InstalledFlow to authenticate. The
//!     // authentication tokens are persisted to a file named tokencache.json. The
//!     // authenticator takes care of caching tokens to disk and refreshing tokens once
//!     // they've expired.
//!     let mut auth = InstalledFlowAuthenticator::builder(secret, InstalledFlowReturnMethod::HTTPRedirect)
//!     .persist_tokens_to_disk("tokencache.json")
//!     .build()
//!     .await
//!     .unwrap();
//!
//!     let scopes = &["https://www.googleapis.com/auth/drive.file"];
//!
//!     // token(<scopes>) is the one important function of this crate; it does everything to
//!     // obtain a token that can be sent e.g. as Bearer token.
//!     match auth.token(scopes).await {
//!         Ok(token) => println!("The token is {:?}", token),
//!         Err(e) => println!("error: {:?}", e),
//!     }
//! }
//! ```
//!
#![deny(missing_docs)]
mod application_default_credentials;
pub mod authenticator;
pub mod authenticator_delegate;
mod device;
pub mod error;
mod helper;
mod installed;
mod refresh;
mod service_account;

/// Interface for storing tokens so that they can be re-used. There are built-in memory and
/// file-based storage providers. You can implement your own by implementing the TokenStorage trait.
pub mod storage;

mod types;

#[doc(inline)]
pub use crate::authenticator::{
    ApplicationDefaultCredentialsAuthenticator, DeviceFlowAuthenticator,
    InstalledFlowAuthenticator, ServiceAccountAuthenticator,
};

pub use crate::helper::*;
pub use crate::installed::InstalledFlowReturnMethod;

pub use crate::service_account::ServiceAccountKey;

#[doc(inline)]
pub use crate::error::Error;
pub use crate::types::{AccessToken, ApplicationSecret, ConsoleApplicationSecret};
