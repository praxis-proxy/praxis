// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Start a proxy after an embedded service initializes on the network backend.

use std::{sync::Arc, time::Duration};

use praxis::{RuntimeService, RuntimeServiceContext, RuntimeServiceFuture, ServerComposition};
use praxis_core::config::Config;

/// Represents a process-lifetime service with asynchronous initialization.
struct ExampleService;

impl RuntimeService for ExampleService {
    fn run(self: Arc<Self>, context: RuntimeServiceContext) -> RuntimeServiceFuture {
        Box::pin(async move {
            let (mut shutdown, ready) = context.into_parts();
            tokio::select! {
                () = shutdown.requested() => return,
                () = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
            ready.notify_ready();
            shutdown.requested().await;
        })
    }
}

/// Run the example with the bundled configuration.
fn main() -> Result<(), praxis::StartupError> {
    let config = Config::from_yaml(include_str!(
        "../../../examples/configs/operations/runtime-services.yaml"
    ))?;
    let composition = ServerComposition::standard().add_runtime_service("example-service", ExampleService);
    praxis::try_run_server_with_composition(config, composition, None, None)
}
