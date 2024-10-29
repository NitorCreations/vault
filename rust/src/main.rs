#[tokio::main]
async fn main() -> anyhow::Result<()> {
    nitor_vault::args::run_cli().await
}
