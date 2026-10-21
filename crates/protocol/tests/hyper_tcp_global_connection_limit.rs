// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

#![forbid(unsafe_code)]

//! The process-wide connection limit on a hyper TCP listener, in its own
//! binary.
//!
//! The limit is a process-wide `OnceLock`: installing a ceiling of one in
//! the crate's unit-test binary would refuse the connections every other
//! test there opens through the same admission path.

/// A hyper TCP listener under a global limit of one connection, compiled
/// only with the hyper backend.
#[cfg(feature = "hyper")]
#[expect(
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "integration tests are in tests/ directory, not in src"
)]
mod with_global_limit {
    use std::{
        collections::HashMap,
        io::{self, Read as _, Write as _},
        net::{TcpListener, TcpStream},
        thread,
        time::{Duration, Instant},
    };

    use praxis_core::{
        config::Config,
        server::{HyperRuntime, ServerRuntime as _},
    };
    use praxis_protocol::{ListenerPipelines, connections::init_global_limit, tcp::HyperTcp};
    use tokio::sync::oneshot;

    #[test]
    fn excess_tcp_connection_is_refused_until_a_slot_frees() {
        init_global_limit(1);
        let echo = echo_backend();
        let addr = free_addr();
        let _running = start(&addr, &echo);

        let mut first = connect(&addr);
        first.write_all(b"one").unwrap();
        let echoed = read_exactly(&mut first, 3);
        let mut excess = connect(&addr);
        drop(excess.write_all(b"two"));
        let refused = closed_by_peer(&mut excess);
        drop(first);

        assert_eq!(echoed, b"one", "the first connection is forwarded");
        assert!(
            refused,
            "a connection past the global limit is closed without being forwarded"
        );
        assert!(
            eventually_forwarded(&addr),
            "the slot frees once the first connection ends"
        );
    }

    // -------------------------------------------------------------------------
    // Test Utilities
    // -------------------------------------------------------------------------

    /// A `HyperRuntime` serving on its own thread until dropped.
    struct Running {
        /// Resolves the runtime's shutdown future.
        stop: Option<oneshot::Sender<()>>,

        /// The thread `run_with_shutdown` blocks.
        thread: Option<thread::JoinHandle<()>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                _ = stop.send(());
            }
            if let Some(thread) = self.thread.take() {
                drop(thread.join());
            }
        }
    }

    /// Whether the peer closed `stream`: a read sees the end of the stream or
    /// a reset, not data or the read timeout.
    fn closed_by_peer(stream: &mut TcpStream) -> bool {
        match stream.read(&mut [0_u8; 16]) {
            Ok(read) => read == 0,
            Err(err) => !matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
        }
    }

    /// Connect to `addr` once its listener is up, with a read timeout so a
    /// broken proxy fails the test instead of hanging it.
    #[expect(clippy::disallowed_methods, reason = "blocking test utility, not async")]
    fn connect(addr: &str) -> TcpStream {
        let started = Instant::now();
        let stream = loop {
            match TcpStream::connect(addr) {
                Ok(stream) => break stream,
                Err(err) => {
                    assert!(
                        started.elapsed() < Duration::from_secs(5),
                        "{addr} never started listening: {err}"
                    );
                    thread::sleep(Duration::from_millis(10));
                },
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream
    }

    /// Start a loopback echo server and return its address.
    fn echo_backend() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut writer) = stream else { break };
                let mut reader = writer.try_clone().unwrap();
                thread::spawn(move || io::copy(&mut reader, &mut writer));
            }
        });
        addr
    }

    /// Whether a new connection to `addr` is forwarded within five seconds;
    /// the proxy frees a slot only once it sees the old connection end.
    #[expect(clippy::disallowed_methods, reason = "blocking test utility, not async")]
    fn eventually_forwarded(addr: &str) -> bool {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            let mut client = connect(addr);
            let mut echoed = [0_u8; 5];
            if client.write_all(b"three").is_ok() && client.read_exact(&mut echoed).is_ok() {
                return &echoed == b"three";
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// A loopback address with a port nothing is listening on right now.
    fn free_addr() -> String {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().to_string()
    }

    /// Read exactly `len` bytes from `stream`.
    fn read_exactly(stream: &mut TcpStream, len: usize) -> Vec<u8> {
        let mut buf = vec![0_u8; len];
        stream.read_exact(&mut buf).unwrap();
        buf
    }

    /// Register a TCP listener on `addr` forwarding to `upstream` on a fresh
    /// runtime and start it.
    fn start(addr: &str, upstream: &str) -> Running {
        let config = Config::from_yaml(&format!(
            "runtime:\n  threads: 2\ninsecure_options:\n  allow_private_upstreams: true\nlisteners:\n  - name: capped\n    \
             address: \"{addr}\"\n    protocol: tcp\n    upstream: \"{upstream}\"\n"
        ))
        .unwrap();
        let mut runtime = HyperRuntime::new(&config);
        let pipelines = ListenerPipelines::new(HashMap::new());
        let _watchers = HyperTcp::register_on(&mut runtime, &config, &pipelines).unwrap();
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = thread::spawn(move || {
            runtime.run_with_shutdown(Box::pin(async move {
                _ = stopped.await;
            }));
        });
        Running {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}
