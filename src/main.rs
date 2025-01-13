use color_eyre::Result;
use gadget_logging::info;
use gadget_runners::core::runner::BlueprintRunner;
use wsts_blueprint::context::WstsContext;

#[gadget_macros::main(env)]
async fn main() {
    let context = WstsContext::new(env.clone())?;

    info!(
        "Starting the Blueprint Runner for {} ...",
        hex::encode(context.identity.public().as_ref())
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
