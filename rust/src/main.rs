use nitor_vault::Vault;

#[tokio::main]
async fn main() {
    println!("Nitor Vault, see https://github.com/nitorcreations/vault for usage examples");
    println!("testing listing all vault items...");
    let client = Vault::new(None, None).await.expect("Error getting Vault");
    list_all(&client).await;
    // client
    //     .store("testingtesting", "hello team".as_bytes())
    //     .await;
    // println!("{}", client.lookup("testingtesting").await.unwrap())
}

async fn list_all(vault: &Vault) {
    match vault.all().await {
        Ok(all) => println!("{}", all.join("\n")),
        Err(error) => println!("error occurred: {}", error),
    }
}
