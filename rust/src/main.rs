use vault::Vault;

#[tokio::main]
async fn main() {
    let client = Vault::new(None, None).await;
    // client.list_all().await;
    // client
    //     .store("testingtesting", "hello team".as_bytes())
    //     .await;
    println!("{}", client.lookup("testingtesting").await)
}
