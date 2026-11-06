// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Seeded legal action sequences compared with an independent byte model.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::field_reassign_with_default,
    reason = "test assertions and generated cases"
)]

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use praxis_filter::{
    BodyAccess, BodyMode, FilterAction, FilterError, FilterFactory, FilterPipeline, FilterRegistry, HttpFilter,
    HttpFilterContext, Request,
};

use super::{
    request_body_filter::run_request_body,
    request_filter::stream_buffer::{PreReadPass, PreReadStop},
};
use crate::http::pingora::context::PingoraRequestCtx;

/// Legal read-only filter actions; release may repeat without releasing twice.
#[derive(Clone, Copy, Debug)]
enum Action {
    /// Leave delivery mode and future callbacks unchanged.
    Continue,
    /// Stop future callbacks to this filter.
    Done,
    /// Request release while allowing subsequent callbacks.
    Release,
}

/// One callback observation, copied so the observer cannot retain input owners.
type Observation = (bool, Vec<u8>);

/// Scripted filter independent of the test's expected byte accounting.
struct Script {
    /// One legal action for each observed callback.
    actions: Vec<Action>,
    /// Observed content and EOS flags, without retaining the input allocation.
    observed: Arc<Mutex<Vec<Observation>>>,
    /// Framework buffering and original input ceiling.
    limit: usize,
}

#[async_trait::async_trait]
impl HttpFilter for Script {
    fn name(&self) -> &'static str {
        "body_model_script"
    }

    async fn on_request(&self, _: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        Ok(FilterAction::Continue)
    }

    fn request_body_access(&self) -> BodyAccess {
        BodyAccess::ReadOnly
    }

    fn request_body_mode(&self) -> BodyMode {
        BodyMode::StreamBuffer {
            max_bytes: Some(self.limit),
        }
    }

    async fn on_request_body(
        &self,
        _: &mut HttpFilterContext<'_>,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) -> Result<FilterAction, FilterError> {
        let mut observed = self.observed.lock().unwrap();
        let action = self.actions.get(observed.len()).copied().unwrap_or(Action::Continue);
        observed.push((end_of_stream, body.as_deref().unwrap_or_default().to_vec()));
        drop(observed);
        Ok(match action {
            Action::Continue => FilterAction::Continue,
            Action::Done => FilterAction::BodyDone,
            Action::Release => FilterAction::Release,
        })
    }
}

/// Fixed generator with a printed seed sufficient to replay any failure.
fn next(state: &mut u64) -> usize {
    *state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    usize::try_from(*state >> 32).unwrap()
}

/// Generated input and action script. Empty chunks and no-data hooks are distinct.
struct Case {
    /// Input byte ceiling for this case.
    limit: usize,
    /// Input owners and no-data callbacks before EOS.
    chunks: Vec<Option<Arc<[u8]>>>,
    /// Deterministically selected read-only actions.
    actions: Vec<Action>,
}

impl Case {
    /// Generate bounded candidates with varying sizes and partitions.
    fn generated(seed: u64, pre_read: bool) -> Self {
        let mut random = seed;
        let limit = 1 + next(&mut random) % 32;
        let size = next(&mut random) % 41;
        let bytes: Vec<_> = (0..size).map(|index| u8::try_from(index).unwrap()).collect();
        let mut chunks = Vec::new();
        let mut offset = 0;
        while offset < size {
            if next(&mut random).is_multiple_of(2) {
                chunks.push(Some(Arc::from([])));
            }
            if !pre_read && next(&mut random).is_multiple_of(3) {
                chunks.push(None);
            }
            let end = (offset + 1 + next(&mut random) % 7).min(size);
            chunks.push(Some(Arc::from(bytes.get(offset..end).unwrap())));
            offset = end;
        }
        let actions = std::iter::repeat_with(|| match next(&mut random) % 5 {
            0 => Action::Done,
            1 | 2 => Action::Release,
            _ => Action::Continue,
        })
        .take(64)
        .collect();
        Self { limit, chunks, actions }
    }

    /// Construct the real framework pipeline for the generated script.
    fn pipeline(&self, observed: &Arc<Mutex<Vec<Observation>>>) -> FilterPipeline {
        let actions = self.actions.clone();
        let observed = Arc::clone(observed);
        let limit = self.limit;
        let mut registry = FilterRegistry::with_builtins();
        registry
            .register(
                "body_model_script",
                FilterFactory::Http(Arc::new(move |_| {
                    Ok(Box::new(Script {
                        actions: actions.clone(),
                        observed: Arc::clone(&observed),
                        limit,
                    }))
                })),
            )
            .unwrap();
        let mut entries: Vec<praxis_filter::FilterEntry> =
            serde_yaml::from_str("- filter: body_model_script\n").unwrap();
        let mut pipeline = FilterPipeline::build(&mut entries, &registry).unwrap();
        pipeline.apply_body_limits(Some(limit), None, false).unwrap();
        pipeline
    }

    /// Verify that cancellation or completion left no retained input owner.
    fn assert_released(&self, seed: u64) {
        for owner in self.chunks.iter().flatten() {
            assert_eq!(
                Arc::strong_count(owner),
                1,
                "input retained after teardown: seed={seed}"
            );
        }
    }
}

/// Independent model uses plain bytes and its own callback/action position.
#[derive(Default)]
struct Model {
    /// Original bytes admitted before any crossing chunk.
    accepted: Vec<u8>,
    /// Complete bytes emitted by the expected delivery lifecycle.
    forwarded: Vec<u8>,
    /// Expected invocations of the scripted filter.
    calls: Vec<Observation>,
    /// A `BodyDone` action prevents further calls to this filter.
    done: bool,
    /// A `Release` action ends normal buffering but does not finish a pre-read.
    released: bool,
}

impl Model {
    /// Advance only the independent filter-action state.
    fn observe(&mut self, bytes: &[u8], eos: bool, actions: &[Action]) {
        if !self.done {
            let action = actions.get(self.calls.len()).copied().unwrap_or(Action::Continue);
            self.calls.push((eos, bytes.to_vec()));
            match action {
                Action::Continue => {},
                Action::Done => self.done = true,
                Action::Release => self.released = true,
            }
        }
    }
}

/// Minimal snapshot needed by actual body-phase context construction.
fn request() -> Request {
    Request {
        method: http::Method::POST,
        uri: "/model".parse().unwrap(),
        headers: http::HeaderMap::new(),
    }
}

#[tokio::test]
async fn generated_normal_body_actions_match_byte_model() {
    for seed in 0..256 {
        let case = Case::generated(seed, false);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let pipeline = case.pipeline(&observed);
        let mut ctx = PingoraRequestCtx::default();
        ctx.request_snapshot = Some(request());
        ctx.request_body_mode = BodyMode::StreamBuffer {
            max_bytes: Some(case.limit),
        };
        let mut model = Model::default();
        // Some runs cancel before EOS, exposing buffer ownership as well as bytes.
        let cancel = seed.is_multiple_of(7);
        let callbacks = case.chunks.len() + usize::from(!cancel);
        for index in 0..callbacks {
            let eos = index == case.chunks.len();
            let chunk = case.chunks.get(index).and_then(Option::as_ref);
            let bytes = chunk.map_or(&[][..], |owner| owner.as_ref());
            let total = model.accepted.len() + bytes.len();
            let mut body = chunk.map(|owner| Bytes::from_owner(Arc::clone(owner)));
            let result = run_request_body(&pipeline, &mut body, eos, &mut ctx).await;
            assert_eq!(result.is_ok(), total <= case.limit, "seed={seed}, callback={index}");
            assert_eq!(
                ctx.request_body_bytes,
                u64::try_from(total).unwrap(),
                "seed={seed}, callback={index}"
            );
            if let Err(halt) = result {
                assert_eq!(halt.rejection.unwrap().status, 413, "seed={seed}");
                break;
            }
            model.accepted.extend_from_slice(bytes);
            let was_released = model.released;
            let seen = if eos && !was_released {
                model.accepted.clone()
            } else {
                bytes.to_vec()
            };
            model.observe(&seen, eos, &case.actions);
            let expected = if was_released {
                bytes.to_vec()
            } else if model.released || eos {
                model.accepted.clone()
            } else {
                Vec::new()
            };
            assert_eq!(
                body.as_deref().unwrap_or_default(),
                expected,
                "seed={seed}, callback={index}"
            );
            model.forwarded.extend_from_slice(&expected);
            assert_eq!(*observed.lock().unwrap(), model.calls, "seed={seed}, callback={index}");
            if eos {
                assert_eq!(model.forwarded, model.accepted, "conservation: seed={seed}");
            }
        }
        drop(ctx);
        case.assert_released(seed);
    }
}

#[tokio::test]
async fn generated_pre_read_actions_match_separate_byte_model() -> Result<(), FilterError> {
    for seed in 0..256 {
        let case = Case::generated(seed, true);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let pipeline = case.pipeline(&observed);
        let mut ctx = PingoraRequestCtx::default();
        let snapshot = request();
        let mut pass = PreReadPass::new(&pipeline).unwrap();
        let mut model = Model::default();
        let cancel = seed.is_multiple_of(7);
        let callbacks = case.chunks.len() + usize::from(!cancel);
        let mut finished = false;
        for index in 0..callbacks {
            let eos = index == case.chunks.len();
            let chunk = case.chunks.get(index).and_then(Option::as_ref);
            let bytes = chunk.map_or(&[][..], |owner| owner.as_ref());
            let total = model.accepted.len() + bytes.len();
            let body = chunk.map(|owner| Bytes::from_owner(Arc::clone(owner)));
            let result = pass.feed(&pipeline, &mut ctx, &snapshot, body).await;
            assert_eq!(result.is_ok(), total <= case.limit, "seed={seed}, callback={index}");
            assert_eq!(
                ctx.request_body_bytes,
                u64::try_from(total).unwrap(),
                "seed={seed}, callback={index}"
            );
            match result {
                Err(PreReadStop::Rejected(rejection)) => {
                    assert_eq!(rejection.status, 413, "seed={seed}");
                    break;
                },
                Err(PreReadStop::Filter(error)) => {
                    return Err(format!("unexpected filter failure: seed={seed}: {error}").into());
                },
                Ok(complete) => assert_eq!(complete, eos, "Release must not finish pre-read: seed={seed}"),
            }
            model.accepted.extend_from_slice(bytes);
            let seen = if eos { model.accepted.clone() } else { bytes.to_vec() };
            model.observe(&seen, eos, &case.actions);
            assert_eq!(*observed.lock().unwrap(), model.calls, "seed={seed}, callback={index}");
            finished = eos;
        }
        if finished {
            pass.finish(&pipeline, &mut ctx);
            let output: Vec<_> = ctx
                .pre_read_body
                .as_ref()
                .unwrap()
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect();
            assert_eq!(output, model.accepted, "pre-read byte conservation: seed={seed}");
        } else {
            drop(pass);
        }
        drop(ctx);
        case.assert_released(seed);
    }
    Ok(())
}
