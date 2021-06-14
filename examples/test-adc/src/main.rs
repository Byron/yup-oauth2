use yup_oauth2::authenticator::ApplicationDefaultCredentialsTypes;
use yup_oauth2::ApplicationDefaultCredentialsAuthenticator;

#[tokio::main]
async fn main() {
    let auth = match ApplicationDefaultCredentialsAuthenticator::builder().await {
        ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth
            .build()
            .await
            .expect("Unable to create instance metadata authenticator"),
        ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth
            .build()
            .await
            .expect("Unable to create service account authenticator"),
    };
    let scopes = &["https://www.googleapis.com/auth/pubsub"];

    let tok = auth.token(scopes).await.unwrap();
    println!("token is: {:?}", tok);
}
