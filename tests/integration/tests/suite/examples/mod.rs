mod test_utils;
pub(crate) use test_utils::load_example_config;

mod access_logging;
mod api_key_filter;
mod basic_reverse_proxy;
mod canary_routing;
mod conditional_filters;
mod default_config;
mod health_checks;
mod header_manipulation;
mod least_connections;
mod logging;
mod max_body_guard;
#[cfg(feature = "ai-inference")]
mod model_to_header;
mod multi_listener;
mod path_based_routing;
mod round_robin;
mod session_affinity;
mod static_response;
mod stream_buffer;
mod timeout;
mod virtual_hosts;
mod weighted_load_balancing;
