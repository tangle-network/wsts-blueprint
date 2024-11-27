use color_eyre::Result;
use gadget_sdk::info;
use gadget_sdk::runners::tangle::TangleConfig;
use gadget_sdk::runners::BlueprintRunner;
use gadget_sdk::subxt::ext::sp_core::Pair;
use wsts_blueprint::context::WstsContext;

#[gadget_sdk::main(env)]
async fn main() {
    let context = WstsContext::new(env.clone())?;

    info!(
        "Starting the Blueprint Runner for {} ...",
        hex::encode(context.identity.public().as_ref())
    );

    info!("~~~ Executing the WSTS blueprint ~~~");

    let tangle_config = TangleConfig::default();
    let keygen = wsts_blueprint::keygen::KeygenEventHandler::new(&env, context.clone()).await?;

    BlueprintRunner::new(tangle_config, env.clone())
        .job(keygen)
        .run()
        .await?;

    info!("Exiting...");
    Ok(())
}
