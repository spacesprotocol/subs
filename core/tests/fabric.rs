use fabric::client::Fabric;

#[tokio::test]
async fn test_fabric() -> anyhow::Result<()> {
    let fabric = Fabric::with_seeds(&["http://127.0.0.1:7779"]);

    fabric.bootstrap().await.expect("bootstrap");

    Ok(())
}
