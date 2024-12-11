#[cfg(test)]
mod e2e {
    use ::blueprint_test_utils::test_ext::new_test_ext_blueprint_manager;
    pub use ::blueprint_test_utils::{
        run_test_blueprint_manager, setup_log, submit_job, wait_for_completion_of_tangle_job, Job,
    };
    use blueprint_test_utils::tangle::NodeConfig;
    use blueprint_test_utils::*;
    use wsts_blueprint::keygen::KEYGEN_JOB_ID;
    use wsts_blueprint::signing::SIGN_JOB_ID;

    const N: usize = 3;
    const T: usize = 2;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_blueprint() {
        setup_log();

        let tmp_dir = ::blueprint_test_utils::tempfile::TempDir::new().unwrap();
        let tmp_dir_path = format!("{}", tmp_dir.path().display());

        new_test_ext_blueprint_manager::<N, 1, String, _, _>(
            tmp_dir_path,
            run_test_blueprint_manager,
            NodeConfig::new(false),
        )
            .await
            .execute_with_async(|client, handles, blueprint, _| async move {
                let keypair = handles[0].sr25519_id().clone();
                let service = &blueprint.services[KEYGEN_JOB_ID as usize];

                let service_id = service.id;
                gadget_sdk::info!(
            "Submitting KEYGEN job {KEYGEN_JOB_ID} with service ID {service_id}",
        );

                let job_args = vec![(InputValue::Uint16(T as u16))];
                let call_id = get_next_call_id(client)
                    .await
                    .expect("Failed to get next job id")
                    .saturating_sub(1);
                let job = submit_job(
                    client,
                    &keypair,
                    service_id,
                    Job::from(KEYGEN_JOB_ID),
                    job_args,
                    call_id,
                )
                    .await
                    .expect("Failed to submit job");

                let keygen_call_id = job.call_id;

                gadget_sdk::info!(
            "Submitted KEYGEN job {} with service ID {service_id} has call id {keygen_call_id}",
            KEYGEN_JOB_ID
        );

                let job_results = wait_for_completion_of_tangle_job(client, service_id, keygen_call_id, T)
                    .await
                    .expect("Failed to wait for job completion");

                assert_eq!(job_results.service_id, service_id);
                assert_eq!(job_results.call_id, keygen_call_id);

                let expected_outputs = vec![];
                if !expected_outputs.is_empty() {
                    assert_eq!(
                        job_results.result.len(),
                        expected_outputs.len(),
                        "Number of keygen outputs doesn't match expected"
                    );

                    for (result, expected) in job_results
                        .result
                        .into_iter()
                        .zip(expected_outputs.into_iter())
                    {
                        assert_eq!(result, expected);
                    }
                } else {
                    gadget_sdk::info!("No expected outputs specified, skipping keygen verification");
                }

                gadget_sdk::info!("Keygen job completed successfully! Moving on to signing ...");

                let service = &blueprint.services[0];
                let service_id = service.id;
                gadget_sdk::info!(
                    "Submitting SIGNING job {} with service ID {service_id}",
                    SIGN_JOB_ID
                );

                let job_args = vec![
                    InputValue::Uint64(keygen_call_id),
                    InputValue::List(BoundedVec(vec![
                        InputValue::Uint8(1),
                        InputValue::Uint8(2),
                        InputValue::Uint8(3),
                    ])),
                ];

                let job = submit_job(
                    client,
                    &keypair,
                    service_id,
                    Job::from(SIGN_JOB_ID),
                    job_args,
                    call_id + 1,
                )
                    .await
                    .expect("Failed to submit job");

                let signing_call_id = job.call_id;
                gadget_sdk::info!(
            "Submitted SIGNING job {SIGN_JOB_ID} with service ID {service_id} has call id {signing_call_id}",
        );

                let job_results = wait_for_completion_of_tangle_job(client, service_id, signing_call_id, T)
                    .await
                    .expect("Failed to wait for job completion");

                let expected_outputs = vec![];
                if !expected_outputs.is_empty() {
                    assert_eq!(
                        job_results.result.len(),
                        expected_outputs.len(),
                        "Number of signing outputs doesn't match expected"
                    );

                    for (result, expected) in job_results
                        .result
                        .into_iter()
                        .zip(expected_outputs.into_iter())
                    {
                        assert_eq!(result, expected);
                    }
                } else {
                    gadget_sdk::info!("No expected outputs specified, skipping signing verification");
                }
            })
            .await
    }
}
