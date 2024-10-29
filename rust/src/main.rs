#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nitor_vault::run_cli().await
}
