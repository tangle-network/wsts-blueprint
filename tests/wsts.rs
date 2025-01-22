#[cfg(test)]
mod e2e {
    use blueprint_sdk::logging::setup_log;
    use blueprint_sdk::testing::tangle::{InputValue, TangleTestHarness};
    use blueprint_sdk::testing::tempfile;
    use blueprint_sdk::testing::utils::harness::TestHarness;
    use blueprint_sdk::testing::utils::runner::TestEnv;
    use blueprint_sdk::tokio;
    use wsts_blueprint::context::WstsContext;
    use wsts_blueprint::keygen::KEYGEN_JOB_ID;
    use wsts_blueprint::signing::SIGN_JOB_ID;
    use wsts_blueprint::tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;

    const T: usize = 2;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_blueprint() -> Result<(), Box<dyn std::error::Error>> {
        setup_log();

        // Initialize test harness (node, keys, deployment)
        let temp_dir = tempfile::TempDir::new()?;
        let harness = TangleTestHarness::setup(temp_dir).await?;
        let env = harness.env().clone();

        // Create blueprint-specific context
        let blueprint_ctx = WstsContext::new(env.clone())?;

        // Initialize event handler
        let keygen_handler =
            wsts_blueprint::keygen::KeygenEventHandler::new(&env.clone(), blueprint_ctx.clone())
                .await?;

        let signing_handler =
            wsts_blueprint::signing::SignEventHandler::new(&env.clone(), blueprint_ctx).await?;

        // Setup service
        let (mut test_env, service_id) = harness.setup_services().await?;
        test_env.add_job(keygen_handler);
        test_env.add_job(signing_handler);

        tokio::spawn(async move {
            test_env.run_runner().await.unwrap();
        });

        // Execute job and verify result
        let keygen_result = harness
            .execute_job(
                service_id,
                KEYGEN_JOB_ID,
                vec![(InputValue::Uint16(T as u16))],
                vec![],
            )
            .await?;

        assert_eq!(keygen_result.service_id, service_id);

        let results = harness
            .execute_job(
                service_id,
                SIGN_JOB_ID,
                vec![
                    InputValue::Uint64(keygen_result.call_id),
                    InputValue::List(BoundedVec(vec![
                        InputValue::Uint8(1),
                        InputValue::Uint8(2),
                        InputValue::Uint8(3),
                    ])),
                ],
                vec![],
            )
            .await?;

        assert_eq!(results.service_id, service_id);

        Ok(())
    }
}
