use blueprint_sdk::logging::info;
use blueprint_sdk::macros;
use blueprint_sdk::runners::core::runner::BlueprintRunner;
use blueprint_sdk::runners::tangle::tangle::TangleConfig;
use color_eyre::Result;
use wsts_blueprint::context::WstsContext;
use wsts_blueprint::crypto::KeyEncoding;

#[macros::main(env)]
async fn main() {
    let context = WstsContext::new(env.clone())?;

    info!(
        "Starting the Blueprint Runner for {} ...",
        hex::encode(context.identity.public().to_bytes())
    );

    info!("~~~ Executing the WSTS blueprint ~~~");

    let tangle_config = TangleConfig::default();
    let keygen = wsts_blueprint::keygen::KeygenEventHandler::new(&env, context.clone()).await?;
    let signing = wsts_blueprint::signing::SignEventHandler::new(&env, context.clone()).await?;

    BlueprintRunner::new(tangle_config, env.clone())
        .job(keygen)
        .job(signing)
        .run()
        .await?;

    info!("Exiting...");
    Ok(())
}
