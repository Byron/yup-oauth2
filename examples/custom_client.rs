//! This example demonstrates how to use the same connection pool for both obtaining the tokens and
//! using the API that these tokens authorize. In most cases e.g. obtaining the service account key
//! will already establish a keep-alive http connection, so the succeeding API call should be much
//! faster.
//!
//! It is also a better use of resources (memory, sockets, etc.)

async fn r#use<C>(
    client: hyper::Client<C>,
    authenticator: yup_oauth2::authenticator::Authenticator<C>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    C: Clone + Send + Sync + hyper::client::connect::Connect + 'static,
{
    let token = authenticator.token(&["email"]).await?;
    let request = http::Request::get("https://example.com")
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token.access_token().ok_or("no access token")?),
        )
        .body(hyper::body::Body::empty())?;
    let response = client.request(request).await?;
    drop(response); // Implementing handling of the response is left as an exercise for the reader.
    Ok(())
}

#[tokio::main]
async fn main() {
    let google_credentials = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .expect("env var GOOGLE_APPLICATION_CREDENTIALS is required");
    let secret = yup_oauth2::read_service_account_key(google_credentials)
        .await
        .expect("$GOOGLE_APPLICATION_CREDENTIALS is not a valid service account key");
    let client = hyper::Client::builder().build(hyper_rustls::HttpsConnector::with_native_roots());
    let authenticator =
        yup_oauth2::ServiceAccountAuthenticator::with_client(secret, client.clone())
            .build()
            .await
            .expect("could not create an authenticator");
    r#use(client, authenticator)
        .await
        .expect("use is successful!");
}
