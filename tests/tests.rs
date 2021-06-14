use yup_oauth2::{
    authenticator::Authenticator,
    authenticator_delegate::{DeviceAuthResponse, DeviceFlowDelegate, InstalledFlowDelegate},
    error::{AuthError, AuthErrorCode},
    ApplicationDefaultCredentialsAuthenticator, ApplicationSecret, DeviceFlowAuthenticator, Error,
    InstalledFlowAuthenticator, InstalledFlowReturnMethod, ServiceAccountAuthenticator,
    ServiceAccountKey,
};

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use httptest::{matchers::*, responders::json_encoded, Expectation, Server};
use hyper::client::connect::HttpConnector;
use hyper::Uri;
#[cfg(not(feature = "hyper-tls"))]
use hyper_rustls::HttpsConnector;
#[cfg(feature = "hyper-tls")]
use hyper_tls::HttpsConnector;
use url::form_urlencoded;

/// Utility function for parsing json. Useful in unit tests. Simply wrap the
/// json! macro in a from_value to deserialize the contents to arbitrary structs.
macro_rules! parse_json {
    ($($json:tt)+) => {
        ::serde_json::from_value(::serde_json::json!($($json)+)).expect("failed to deserialize")
    }
}

async fn create_device_flow_auth(server: &Server) -> Authenticator<HttpsConnector<HttpConnector>> {
    let app_secret: ApplicationSecret = parse_json!({
        "client_id": "902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com",
        "project_id": "yup-test-243420",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": server.url_str("/token"),
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": "iuMPN6Ne1PD7cos29Tk9rlqH",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob","http://localhost"],
    });
    struct FD;
    impl DeviceFlowDelegate for FD {
        fn present_user_code<'a>(
            &'a self,
            pi: &'a DeviceAuthResponse,
        ) -> Pin<Box<dyn Future<Output = ()> + 'a + Send>> {
            assert_eq!("https://example.com/verify", pi.verification_uri);
            Box::pin(async {})
        }
    }

    DeviceFlowAuthenticator::builder(app_secret)
        .flow_delegate(Box::new(FD))
        .device_code_url(server.url_str("/code"))
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_device_success() {
    let _ = env_logger::try_init();
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/code"),
            request::body(url_decoded(contains((
                "client_id",
                matches("902216714886")
            )))),
        ])
        .respond_with(json_encoded(serde_json::json!({
            "device_code": "devicecode",
            "user_code": "usercode",
            "verification_url": "https://example.com/verify",
            "expires_in": 1234567,
            "interval": 1
        }))),
    );
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("client_secret", "iuMPN6Ne1PD7cos29Tk9rlqH")),
                contains(("code", "devicecode")),
            ])),
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken",
            "refresh_token": "refreshtoken",
            "token_type": "Bearer",
            "expires_in": 1234567
        }))),
    );

    let auth = create_device_flow_auth(&server).await;
    let token = auth
        .token(&["https://www.googleapis.com/scope/1"])
        .await
        .expect("token failed");
    assert_eq!("accesstoken", token.as_str());
}

#[tokio::test]
async fn test_device_no_code() {
    let _ = env_logger::try_init();
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/code"),
            request::body(url_decoded(contains((
                "client_id",
                matches("902216714886")
            )))),
        ])
        .respond_with(json_encoded(serde_json::json!({
            "error": "invalid_client_id",
            "error_description": "description"
        }))),
    );
    let auth = create_device_flow_auth(&server).await;
    let auth = auth.clone();
    let res = auth.token(&["https://www.googleapis.com/scope/1"]).await;
    assert!(res.is_err());
    assert!(format!("{}", res.unwrap_err()).contains("invalid_client_id"));
}

#[tokio::test]
async fn test_device_no_token() {
    let _ = env_logger::try_init();
    let server = Server::run();
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/code"),
            request::body(url_decoded(contains((
                "client_id",
                matches("902216714886")
            )))),
        ])
        .respond_with(json_encoded(serde_json::json!({
                    "device_code": "devicecode",
                    "user_code": "usercode",
                    "verification_url": "https://example.com/verify",
                    "expires_in": 1234567,
                    "interval": 1
        }))),
    );
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("client_secret", "iuMPN6Ne1PD7cos29Tk9rlqH")),
                contains(("code", "devicecode")),
            ])),
        ])
        .respond_with(json_encoded(serde_json::json!({
            "error": "access_denied"
        }))),
    );
    let auth = create_device_flow_auth(&server).await;
    let res = auth.token(&["https://www.googleapis.com/scope/1"]).await;
    assert!(res.is_err());
    assert!(format!("{}", res.unwrap_err()).contains("access_denied"));
}

async fn create_installed_flow_auth(
    server: &Server,
    method: InstalledFlowReturnMethod,
    filename: Option<PathBuf>,
) -> Authenticator<HttpsConnector<HttpConnector>> {
    let app_secret: ApplicationSecret = parse_json!({
        "client_id": "902216714886-k2v9uei3p1dk6h686jbsn9mo96tnbvto.apps.googleusercontent.com",
        "project_id": "yup-test-243420",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": server.url_str("/token"),
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": "iuMPN6Ne1PD7cos29Tk9rlqH",
        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob","http://localhost"],
    });
    struct FD(hyper::Client<HttpsConnector<HttpConnector>>);
    impl InstalledFlowDelegate for FD {
        /// Depending on need_code, return the pre-set code or send the code to the server at
        /// the redirect_uri given in the url.
        fn present_user_url<'a>(
            &'a self,
            url: &'a str,
            need_code: bool,
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
            use std::str::FromStr;
            Box::pin(async move {
                if need_code {
                    Ok("authorizationcode".to_owned())
                } else {
                    // Parse presented url to obtain redirect_uri with location of local
                    // code-accepting server.
                    let uri = Uri::from_str(url.as_ref()).unwrap();
                    let query = uri.query().unwrap();
                    let parsed = form_urlencoded::parse(query.as_bytes()).into_owned();
                    let mut rduri = None;
                    for (k, v) in parsed {
                        if k == "redirect_uri" {
                            rduri = Some(v);
                            break;
                        }
                    }
                    if rduri.is_none() {
                        return Err("no redirect_uri!".into());
                    }
                    let mut rduri = rduri.unwrap();
                    rduri.push_str("?code=authorizationcode");
                    let rduri = Uri::from_str(rduri.as_ref()).unwrap();
                    // Hit server.
                    self.0
                        .get(rduri)
                        .await
                        .map_err(|e| e.to_string())
                        .map(|_| "".to_string())
                }
            })
        }
    }

    let mut builder =
        InstalledFlowAuthenticator::builder(app_secret, method).flow_delegate(Box::new(FD(
            #[cfg(not(feature = "hyper-tls"))]
            hyper::Client::builder().build(HttpsConnector::with_native_roots()),
            #[cfg(feature = "hyper-tls")]
            hyper::Client::builder().build(HttpsConnector::new()),
        )));

    builder = if let Some(filename) = filename {
        builder.persist_tokens_to_disk(filename)
    } else {
        builder
    };

    builder.build().await.unwrap()
}

#[tokio::test]
async fn test_installed_interactive_success() {
    let _ = env_logger::try_init();
    let server = Server::run();
    let auth =
        create_installed_flow_auth(&server, InstalledFlowReturnMethod::Interactive, None).await;
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("code", "authorizationcode")),
                contains(("client_id", matches("9022167.*"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken",
            "refresh_token": "refreshtoken",
            "token_type": "Bearer",
            "expires_in": 12345678
        }))),
    );

    let tok = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!("accesstoken", tok.as_str());
}

#[tokio::test]
async fn test_installed_redirect_success() {
    let _ = env_logger::try_init();
    let server = Server::run();
    let auth =
        create_installed_flow_auth(&server, InstalledFlowReturnMethod::HTTPRedirect, None).await;
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("code", "authorizationcode")),
                contains(("client_id", matches("9022167.*"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken",
            "refresh_token": "refreshtoken",
            "token_type": "Bearer",
            "expires_in": 12345678
        }))),
    );

    let tok = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!("accesstoken", tok.as_str());
}

#[tokio::test]
async fn test_installed_error() {
    let _ = env_logger::try_init();
    let server = Server::run();
    let auth =
        create_installed_flow_auth(&server, InstalledFlowReturnMethod::Interactive, None).await;
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("code", "authorizationcode")),
                contains(("client_id", matches("9022167.*"))),
            ]))
        ])
        .respond_with(
            http::Response::builder()
                .status(404)
                .body(serde_json::json!({"error": "invalid_code"}).to_string())
                .unwrap(),
        ),
    );

    let tokr = auth.token(&["https://googleapis.com/some/scope"]).await;
    assert!(tokr.is_err());
    assert!(format!("{}", tokr.unwrap_err()).contains("invalid_code"));
}

async fn create_service_account_auth(
    server: &Server,
) -> Authenticator<HttpsConnector<HttpConnector>> {
    let key: ServiceAccountKey = parse_json!({
        "type": "service_account",
        "project_id": "yup-test-243420",
        "private_key_id": "26de294916614a5ebdf7a065307ed3ea9941902b",
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDemmylrvp1KcOn\n9yTAVVKPpnpYznvBvcAU8Qjwr2fSKylpn7FQI54wCk5VJVom0jHpAmhxDmNiP8yv\nHaqsef+87Oc0n1yZ71/IbeRcHZc2OBB33/LCFqf272kThyJo3qspEqhuAw0e8neg\nLQb4jpm9PsqR8IjOoAtXQSu3j0zkXemMYFy93PWHjVpPEUX16NGfsWH7oxspBHOk\n9JPGJL8VJdbiAoDSDgF0y9RjJY5I52UeHNhMsAkTYs6mIG4kKXt2+T9tAyHw8aho\nwmuytQAfydTflTfTG8abRtliF3nil2taAc5VB07dP1b4dVYy/9r6M8Z0z4XM7aP+\nNdn2TKm3AgMBAAECggEAWi54nqTlXcr2M5l535uRb5Xz0f+Q/pv3ceR2iT+ekXQf\n+mUSShOr9e1u76rKu5iDVNE/a7H3DGopa7ZamzZvp2PYhSacttZV2RbAIZtxU6th\n7JajPAM+t9klGh6wj4jKEcE30B3XVnbHhPJI9TCcUyFZoscuPXt0LLy/z8Uz0v4B\nd5JARwyxDMb53VXwukQ8nNY2jP7WtUig6zwE5lWBPFMbi8GwGkeGZOruAK5sPPwY\nGBAlfofKANI7xKx9UXhRwisB4+/XI1L0Q6xJySv9P+IAhDUI6z6kxR+WkyT/YpG3\nX9gSZJc7qEaxTIuDjtep9GTaoEqiGntjaFBRKoe+VQKBgQDzM1+Ii+REQqrGlUJo\nx7KiVNAIY/zggu866VyziU6h5wjpsoW+2Npv6Dv7nWvsvFodrwe50Y3IzKtquIal\nVd8aa50E72JNImtK/o5Nx6xK0VySjHX6cyKENxHRDnBmNfbALRM+vbD9zMD0lz2q\nmns/RwRGq3/98EqxP+nHgHSr9QKBgQDqUYsFAAfvfT4I75Glc9svRv8IsaemOm07\nW1LCwPnj1MWOhsTxpNF23YmCBupZGZPSBFQobgmHVjQ3AIo6I2ioV6A+G2Xq/JCF\nmzfbvZfqtbbd+nVgF9Jr1Ic5T4thQhAvDHGUN77BpjEqZCQLAnUWJx9x7e2xvuBl\n1A6XDwH/ewKBgQDv4hVyNyIR3nxaYjFd7tQZYHTOQenVffEAd9wzTtVbxuo4sRlR\nNM7JIRXBSvaATQzKSLHjLHqgvJi8LITLIlds1QbNLl4U3UVddJbiy3f7WGTqPFfG\nkLhUF4mgXpCpkMLxrcRU14Bz5vnQiDmQRM4ajS7/kfwue00BZpxuZxst3QKBgQCI\nRI3FhaQXyc0m4zPfdYYVc4NjqfVmfXoC1/REYHey4I1XetbT9Nb/+ow6ew0UbgSC\nUZQjwwJ1m1NYXU8FyovVwsfk9ogJ5YGiwYb1msfbbnv/keVq0c/Ed9+AG9th30qM\nIf93hAfClITpMz2mzXIMRQpLdmQSR4A2l+E4RjkSOwKBgQCB78AyIdIHSkDAnCxz\nupJjhxEhtQ88uoADxRoEga7H/2OFmmPsqfytU4+TWIdal4K+nBCBWRvAX1cU47vH\nJOlSOZI0gRKe0O4bRBQc8GXJn/ubhYSxI02IgkdGrIKpOb5GG10m85ZvqsXw3bKn\nRVHMD0ObF5iORjZUqD0yRitAdg==\n-----END PRIVATE KEY-----\n",
        "client_email": "yup-test-sa-1@yup-test-243420.iam.gserviceaccount.com",
        "client_id": "102851967901799660408",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": server.url_str("/token"),
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/yup-test-sa-1%40yup-test-243420.iam.gserviceaccount.com"
    });

    ServiceAccountAuthenticator::builder(key)
        .build()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_service_account_success() {
    use chrono::Utc;
    let _ = env_logger::try_init();
    let server = Server::run();
    let auth = create_service_account_auth(&server).await;

    server.expect(
        Expectation::matching(request::method_path("POST", "/token"))
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "ya29.c.ElouBywiys0LyNaZoLPJcp1Fdi2KjFMxzvYKLXkTdvM-rDfqKlvEq6PiMhGoGHx97t5FAvz3eb_ahdwlBjSStxHtDVQB4ZPRJQ_EOi-iS7PnayahU2S9Jp8S6rk",
            "expires_in": 3600,
            "token_type": "Bearer"
        })))
    );
    let tok = auth
        .token(&["https://www.googleapis.com/auth/pubsub"])
        .await
        .expect("token failed");
    assert!(tok.as_str().contains("ya29.c.ElouBywiys0Ly"));
    assert!(Utc::now() + chrono::Duration::seconds(3600) >= tok.expiration_time().unwrap());
}

#[tokio::test]
async fn test_service_account_error() {
    let _ = env_logger::try_init();
    let server = Server::run();
    let auth = create_service_account_auth(&server).await;
    server.expect(
        Expectation::matching(request::method_path("POST", "/token")).respond_with(json_encoded(
            serde_json::json!({
                "error": "access_denied",
            }),
        )),
    );

    let result = auth
        .token(&["https://www.googleapis.com/auth/pubsub"])
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_refresh() {
    let _ = env_logger::try_init();
    let server = Server::run();
    let auth =
        create_installed_flow_auth(&server, InstalledFlowReturnMethod::Interactive, None).await;
    // We refresh a token whenever it's within 1 minute of expiring. So
    // acquiring a token that expires in 59 seconds will force a refresh on
    // the next token call.
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("code", "authorizationcode")),
                contains(("client_id", matches("^9022167"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken",
            "refresh_token": "refreshtoken",
            "token_type": "Bearer",
            "expires_in": 59,
        }))),
    );
    let tok = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!("accesstoken", tok.as_str());

    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("refresh_token", "refreshtoken")),
                contains(("client_id", matches("^9022167"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken2",
            "token_type": "Bearer",
            "expires_in": 59,
        }))),
    );

    let tok = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!("accesstoken2", tok.as_str());

    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("refresh_token", "refreshtoken")),
                contains(("client_id", matches("^9022167"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken3",
            "token_type": "Bearer",
            "expires_in": 59,
        }))),
    );

    let tok = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!("accesstoken3", tok.as_str());

    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("refresh_token", "refreshtoken")),
                contains(("client_id", matches("^9022167"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "error": "invalid_request",
        }))),
    );

    let tok_err = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect_err("token refresh succeeded unexpectedly");
    match tok_err {
        Error::AuthError(AuthError {
            error: AuthErrorCode::InvalidRequest,
            ..
        }) => {}
        e => panic!("unexpected error on refresh: {:?}", e),
    }
}

#[tokio::test]
async fn test_memory_storage() {
    let _ = env_logger::try_init();
    let server = Server::run();
    let auth =
        create_installed_flow_auth(&server, InstalledFlowReturnMethod::Interactive, None).await;
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("code", "authorizationcode")),
                contains(("client_id", matches("^9022167"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken",
            "refresh_token": "refreshtoken",
            "token_type": "Bearer",
            "expires_in": 12345678,
        }))),
    );

    // Call token twice. Ensure that only one http request is made and
    // identical tokens are returned.
    let token1 = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    let token2 = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!(token1.as_str(), "accesstoken");
    assert_eq!(token1, token2);

    // Create a new authenticator. This authenticator does not share a cache
    // with the previous one. Validate that it receives a different token.
    let auth2 =
        create_installed_flow_auth(&server, InstalledFlowReturnMethod::Interactive, None).await;
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("code", "authorizationcode")),
                contains(("client_id", matches("^9022167"))),
            ]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken2",
            "refresh_token": "refreshtoken2",
            "token_type": "Bearer",
            "expires_in": 12345678,
        }))),
    );
    let token3 = auth2
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!(token3.as_str(), "accesstoken2");
}

#[tokio::test]
async fn test_disk_storage() {
    let _ = env_logger::try_init();
    let server = Server::run();
    let tempdir = tempfile::tempdir().unwrap();
    let storage_path = tempdir.path().join("tokenstorage.json");
    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/token"),
            request::body(url_decoded(all_of![
                contains(("code", "authorizationcode")),
                contains(("client_id", matches("^9022167"))),
            ])),
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken",
            "refresh_token": "refreshtoken",
            "token_type": "Bearer",
            "expires_in": 12345678
        }))),
    );
    {
        let auth = create_installed_flow_auth(
            &server,
            InstalledFlowReturnMethod::Interactive,
            Some(storage_path.clone()),
        )
        .await;

        // Call token twice. Ensure that only one http request is made and
        // identical tokens are returned.
        let token1 = auth
            .token(&["https://googleapis.com/some/scope"])
            .await
            .expect("failed to get token");
        let token2 = auth
            .token(&["https://googleapis.com/some/scope"])
            .await
            .expect("failed to get token");
        assert_eq!(token1.as_str(), "accesstoken");
        assert_eq!(token1, token2);
    }

    // Create a new authenticator. This authenticator uses the same token
    // storage file as the previous one so should receive a token without
    // making any http requests.
    let auth = create_installed_flow_auth(
        &server,
        InstalledFlowReturnMethod::Interactive,
        Some(storage_path.clone()),
    )
    .await;
    // Call token twice. Ensure that identical tokens are returned.
    let token1 = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    let token2 = auth
        .token(&["https://googleapis.com/some/scope"])
        .await
        .expect("failed to get token");
    assert_eq!(token1.as_str(), "accesstoken");
    assert_eq!(token1, token2);
}

#[tokio::test]
async fn test_default_application_credentials_from_metadata_server() {
    use yup_oauth2::authenticator::ApplicationDefaultCredentialsTypes;
    let _ = env_logger::try_init();
    let server = Server::run();
    server.expect(
        // TODO: this does not work.
        Expectation::matching(all_of![
            request::method_path("GET", "/token"),
            request::query(url_decoded(all_of![contains((
                "scopes",
                "https://googleapis.com/some/scope"
            ))]))
        ])
        .respond_with(json_encoded(serde_json::json!({
            "access_token": "accesstoken",
            "refresh_token": "refreshtoken",
            "token_type": "Bearer",
            "expires_in": 12345678,
        }))),
    );
    let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder().await {
        ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth.build().await.unwrap(),
        _ => panic!("We are not testing service account adc model"),
    };
    let token = authenticator
        .token(&["https://googleapis.com/some/scope"])
        .await
        .unwrap();
    assert_ne!(token.as_str(), "accesstoken");
}
