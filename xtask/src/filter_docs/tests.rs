// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Tests for the filter-documentation generation and linting logic.

use super::*;

#[test]
fn to_snake_case_basic() {
    assert_eq!(to_snake_case("Global"), "global", "single word");
    assert_eq!(to_snake_case("PerIp"), "per_ip", "two words");
    assert_eq!(to_snake_case("SomeHTTPMode"), "some_h_t_t_p_mode", "acronym");
}

#[test]
fn capitalize_basic() {
    assert_eq!(capitalize("traffic"), "Traffic", "basic word");
    assert_eq!(capitalize(""), "", "empty string");
}

#[test]
fn first_paragraph_extracts_before_blank_line() {
    let doc = "First line.\nSecond line.\n\nSecond paragraph.";
    assert_eq!(
        first_paragraph(doc),
        "First line. Second line.",
        "should stop at blank line"
    );
}

#[test]
fn first_paragraph_extracts_before_heading() {
    let doc = "Description here.\n# YAML configuration\nstuff";
    assert_eq!(first_paragraph(doc), "Description here.", "should stop at heading");
}

#[test]
fn extract_yaml_examples_basic() {
    let doc = "Some filter.\n\n# YAML configuration\n\n```yaml\nfilter: test\nfoo: bar\n```\n\n# Example\nignored";
    assert_eq!(
        extract_yaml_examples(doc),
        vec!["filter: test\nfoo: bar".to_owned()],
        "should extract yaml block"
    );
}

#[test]
fn extract_yaml_examples_accepts_short_heading() {
    let doc = "Some filter.\n\n# YAML\n\n```yaml\nfilter: test\n```\n";
    assert_eq!(
        extract_yaml_examples(doc),
        vec!["filter: test".to_owned()],
        "should extract short yaml heading"
    );
}

#[test]
fn extract_yaml_examples_accepts_specific_headings() {
    let doc = "Some filter.\n\n# Single-field YAML\n\n```yaml\nfilter: test\nfield: model\n```\n\n# Multi-field YAML\n\n```yaml\nfilter: test\nfields: []\n```\n";
    assert_eq!(
        extract_yaml_examples(doc),
        vec![
            "filter: test\nfield: model".to_owned(),
            "filter: test\nfields: []".to_owned()
        ],
        "specific YAML headings should be extracted in order"
    );
}

#[test]
fn extract_yaml_examples_missing() {
    let doc = "Some filter without yaml.";
    assert_eq!(
        extract_yaml_examples(doc),
        Vec::<String>::new(),
        "should return no examples when no yaml section exists"
    );
}

#[test]
fn config_notes_skip_fenced_code_blocks() {
    let doc = "YAML configuration for a filter.\n\n```rust\nlet yaml = r#\"field: value\"#;\nassert!(true);\n```\n\nAccepts either single-field syntax or multi-field syntax.";
    assert_eq!(
        config_notes(doc),
        vec!["Accepts either single-field syntax or multi-field syntax.".to_owned()],
        "fenced doctests should not render as prose notes"
    );
}

#[test]
fn field_docs_preserve_inline_link_continuation_lines() {
    let doc = "Protocol versions accepted during negotiation.\nEvery entry must be implemented by this build (present in\n[`protocol::SUPPORTED_VERSIONS`]). Defaults to the versions\nthis build implements.";
    assert_eq!(
        normalize_field_doc(doc),
        "Protocol versions accepted during negotiation. Every entry must be implemented by this build (present in [`protocol::SUPPORTED_VERSIONS`]). Defaults to the versions this build implements."
    );
}

#[test]
fn field_docs_skip_reference_definition_lines() {
    let doc = "Uses [`Thing`] for validation.\n\n[`Thing`]: crate::Thing";
    assert_eq!(
        normalize_field_doc(doc),
        "Uses [`Thing`] for validation.",
        "reference definitions should not render inside table cells"
    );
}

#[test]
fn is_config_struct_detects_config() {
    let source = "
            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct MyConfig {
                field: u64,
            }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    if let syn::Item::Struct(s) = &file.items[0] {
        assert!(is_config_struct(s), "should detect config struct");
    } else {
        panic!("expected struct");
    }
}

#[test]
fn is_config_struct_rejects_non_config() {
    let source = "
            #[derive(Debug)]
            struct NotConfig {
                field: u64,
            }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    if let syn::Item::Struct(s) = &file.items[0] {
        assert!(!is_config_struct(s), "should reject non-config struct");
    } else {
        panic!("expected struct");
    }
}

#[test]
fn extract_filter_name_finds_name() {
    let source = r#"
            impl HttpFilter for MyFilter {
                fn name(&self) -> &'static str {
                    "my_filter"
                }
            }
        "#;
    let file: syn::File = syn::parse_str(source).unwrap();
    if let syn::Item::Impl(imp) = &file.items[0] {
        assert_eq!(
            extract_filter_name(imp),
            Some("my_filter".to_owned()),
            "should extract filter name"
        );
    } else {
        panic!("expected impl");
    }
}

#[test]
fn render_filter_doc_has_sections() {
    let result = render_filter_doc(&sample_filter_entry());
    assert!(
        result.starts_with("<!-- Generated by: cargo xtask generate-filter-docs -->"),
        "should have generation comment"
    );
    assert!(result.contains("# `timeout`"), "should have title");
    assert!(result.contains("## Configuration"), "should have config");
    assert!(result.contains("## Example"), "should have example");
}

#[test]
fn render_filter_doc_has_field_row() {
    let result = render_filter_doc(&sample_filter_entry());
    assert!(
        result.contains("| `timeout_ms` | integer | yes | Max time in milliseconds. |"),
        "should have field row"
    );
    assert!(
        result.contains("| Field | Type | Required | Description |"),
        "configuration table should describe requiredness, not fake defaults"
    );
    assert!(result.contains("filter: timeout"), "should have yaml");
}

#[test]
fn is_markdown_link_target_accepts_urls_rejects_intra_doc() {
    assert!(is_markdown_link_target("https://example.com/x"));
    assert!(is_markdown_link_target("http://example.com"));
    assert!(is_markdown_link_target("#anchor"));
    assert!(is_markdown_link_target("./other.md"));
    assert!(!is_markdown_link_target("crate::BodyMode::StreamBuffer"));
    assert!(!is_markdown_link_target("BatchPolicy::First"));
}

#[test]
fn collect_reference_definitions_keeps_urls_only() {
    let doc = "See [RFC 7239] and [`StreamBuffer`].\n\n\
             [RFC 7239]: https://datatracker.ietf.org/doc/html/rfc7239\n\
             [`StreamBuffer`]: crate::BodyMode::StreamBuffer";
    let mut defs = BTreeMap::new();
    collect_reference_definitions(doc, &mut defs);
    assert_eq!(
        defs.get("RFC 7239").map(String::as_str),
        Some("https://datatracker.ietf.org/doc/html/rfc7239")
    );
    assert!(
        !defs.contains_key("`StreamBuffer`"),
        "rustdoc intra-doc targets are not Markdown links"
    );
}

#[test]
fn body_uses_collapsed_reference_distinguishes_link_forms() {
    assert!(body_uses_collapsed_reference("uses [RFC 7239] here", "RFC 7239"));
    assert!(!body_uses_collapsed_reference("inline [RFC 7239](url)", "RFC 7239"));
    assert!(!body_uses_collapsed_reference("def [RFC 7239]: url", "RFC 7239"));
}

#[test]
fn render_link_definitions_appends_only_used_targets() {
    let mut defs = BTreeMap::new();
    defs.insert("RFC 7239".to_owned(), "https://example.com/rfc".to_owned());
    defs.insert("Unused".to_owned(), "https://example.com/unused".to_owned());
    let mut out = "Body references [RFC 7239].\n".to_owned();
    render_link_definitions(&mut out, &defs);
    assert!(
        out.contains("\n[RFC 7239]: https://example.com/rfc\n"),
        "used definition should be appended"
    );
    assert!(!out.contains("Unused"), "unreferenced definitions are not emitted");
}

#[test]
fn tagged_enum_type_str_joins_escaped_variants() {
    let variants = vec!["cookie".to_owned(), "header".to_owned(), "learn".to_owned()];
    assert_eq!(tagged_enum_type_str(&variants), "`cookie` \\| `header` \\| `learn`");
}

#[test]
fn extract_enum_info_captures_internal_tag_and_doc() {
    let item: syn::ItemEnum = syn::parse_str(
        "/// Session persistence mode.\n\
             #[serde(rename_all = \"snake_case\", tag = \"type\")]\n\
             enum P { Cookie { cookie_name: String }, Header { header_name: String } }",
    )
    .expect("parse enum");
    let info = extract_enum_info(&item);
    assert_eq!(info.tag.as_deref(), Some("type"));
    assert!(info.doc.contains("Session persistence mode"));
    assert_eq!(info.variants, vec!["cookie".to_owned(), "header".to_owned()]);
}

#[test]
fn render_filter_doc_strips_fenced_field_docs() {
    let mut entry = sample_filter_entry();
    entry.filter.fields[0].doc =
        "Maximum allowed time.\n\n```rust\nlet yaml = \"timeout_ms: 5000\";\n```\n\nUse `0 | 1` only in tests."
            .to_owned();

    let result = render_filter_doc(&entry);

    assert!(
        result.contains("| `timeout_ms` | integer | yes | Maximum allowed time. Use `0 \\| 1` only in tests. |"),
        "field table rows should render prose without fenced doctests"
    );
    assert!(
        !result.contains("let yaml"),
        "field table rows should not include doctest body text"
    );
}

#[test]
fn render_filter_doc_marks_required_feature() {
    let mut entry = sample_filter_entry();
    entry.required_feature = Some("cpex".to_owned());
    let result = render_filter_doc(&entry);
    assert!(
        result.contains("Requires Cargo feature: `cpex`."),
        "feature-gated filter pages should state the required feature"
    );
}

#[test]
fn deserialize_with_redirect_status_renders_yaml_values() {
    let source = r#"
            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct RedirectConfig {
                /// HTTP redirect status code.
                #[serde(default = "default_status", deserialize_with = "deserialize_redirect_status")]
                status: RedirectStatus,
            }
        "#;
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);
    let filter = build_filter(&items, "redirect", Some("RedirectConfig"));

    assert_eq!(
        filter.fields[0].type_str, "301 \\| 302 \\| 307 \\| 308",
        "custom redirect status deserializer should render accepted YAML values"
    );
}

#[test]
fn scalar_try_from_newtypes_render_scalar_type() {
    let source = r#"
            #[derive(Debug, Deserialize)]
            #[serde(try_from = "u8")]
            struct PrefixLen(u8);

            #[derive(Debug, Deserialize)]
            #[serde(try_from = "RouteRaw")]
            struct Route { path: String }

            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct MyConfig {
                /// Constrained scalar.
                #[serde(default)]
                prefix_len: PrefixLen,
                /// Optional constrained scalar.
                max_len: Option<PrefixLen>,
                /// Struct-backed newtype.
                route: Route,
            }
        "#;
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);
    let filter = build_filter(&items, "test", Some("MyConfig"));

    let types: Vec<&str> = filter.fields.iter().map(|f| f.type_str.as_str()).collect();
    assert_eq!(
        types,
        ["integer", "integer", "Route"],
        "scalar try_from newtypes (plain or optional) render as the scalar; struct-backed ones keep their name"
    );
}

#[test]
fn option_fields_render_optional() {
    let source = "
            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct MyConfig {
                /// Optional field.
                field: Option<String>,
            }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);
    let filter = build_filter(&items, "test", Some("MyConfig"));
    assert_eq!(
        filter.fields[0].required,
        RequiredKind::No,
        "Option fields are optional"
    );
}

#[test]
fn map_types_render_as_objects() {
    let ty: syn::Type = syn::parse_str("BTreeMap<String, String>").unwrap();
    assert_eq!(
        render_type(&ty, &BTreeMap::new()),
        "object<string, string>",
        "maps should render as YAML object shapes"
    );
}

const UNTAGGED_WRAPPER_ENUM_SOURCE: &str = concat!(
    "#[derive(Deserialize)] #[serde(untagged)] enum LoadBalancerStrategy ",
    "{ Simple(SimpleStrategy), Parameterised(ParameterisedStrategy) }",
    "#[derive(Deserialize)] #[serde(rename_all = \"snake_case\")] enum SimpleStrategy ",
    "{ RoundRobin, LeastConnections, #[serde(rename = \"p2c\")] PowerOfTwoChoices }",
    "#[derive(Deserialize)] enum ParameterisedStrategy ",
    "{ #[serde(rename = \"consistent_hash\")] ConsistentHash(ConsistentHashOpts) }",
    "#[derive(Deserialize)] struct ConsistentHashOpts { header: Option<String> }",
    "#[derive(Deserialize)] #[serde(untagged)] enum Endpoint ",
    "{ Simple(String), Weighted { address: String, weight: u32 } }",
);

#[test]
fn manual_deserialize_enum_still_renders_variants() {
    let source = concat!(
        "#[derive(Serialize)] #[serde(untagged)] enum LoadBalancerStrategy ",
        "{ Simple(SimpleStrategy), Parameterised(ParameterisedStrategy) }",
        "impl<'de> Deserialize<'de> for LoadBalancerStrategy { ",
        "fn deserialize<D>(_d: D) -> Result<Self, D::Error> ",
        "where D: serde::Deserializer<'de> { unimplemented!() } }",
        "#[derive(Deserialize)] #[serde(rename_all = \"snake_case\")] enum SimpleStrategy ",
        "{ RoundRobin, LeastConnections }",
        "#[derive(Deserialize)] enum ParameterisedStrategy ",
        "{ #[serde(rename = \"ring_hash\")] RingHash(RingHashOpts) }",
        "#[derive(Deserialize)] struct RingHashOpts { header: Option<String> }",
    );
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);

    let strategy: syn::Type = syn::parse_str("LoadBalancerStrategy").unwrap();
    assert_eq!(
        render_type(&strategy, &items.enums),
        "`round_robin` \\| `least_connections` \\| `ring_hash`",
        "a manual-Deserialize enum must render its variants"
    );
}

#[test]
fn untagged_wrapper_enum_types_render_wrapped_yaml_shapes() {
    let file: syn::File = syn::parse_str(UNTAGGED_WRAPPER_ENUM_SOURCE).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);

    let strategy: syn::Type = syn::parse_str("LoadBalancerStrategy").unwrap();
    assert_eq!(
        render_type(&strategy, &items.enums),
        "`round_robin` \\| `least_connections` \\| `p2c` \\| `consistent_hash`"
    );
    let endpoints: syn::Type = syn::parse_str("Vec<Endpoint>").unwrap();
    assert_eq!(render_type(&endpoints, &items.enums), "(string \\| object)[]");
}

#[test]
fn nested_config_fields_render_dotted_paths() {
    let source = "
            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct OuterConfig {
                /// Header settings.
                #[serde(default)]
                headers: HeaderConfig,
                /// Cluster entries.
                clusters: Vec<ClusterConfig>,
            }

            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct HeaderConfig {
                /// Method header.
                method: Option<String>,
            }

            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ClusterConfig {
                /// Cluster name.
                name: String,
            }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);

    let filter = build_filter(&items, "test", Some("OuterConfig"));
    let names: Vec<&str> = filter.fields.iter().map(|field| field.name.as_str()).collect();
    assert!(names.contains(&"headers.method"), "nested object field should render");
    assert!(names.contains(&"clusters[].name"), "nested list field should render");
}

#[test]
fn flattened_fields_render_at_parent_path() {
    let source = "
            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct OuterConfig { routes: Vec<RouteConfig> }
            #[derive(Debug, Deserialize)]
            struct RouteConfig { #[serde(flatten)] path: PathMatch, cluster: String }
            #[derive(Debug, Deserialize)]
            #[serde(untagged)]
            enum PathMatch { Exact { path: String }, Prefix { path_prefix: String } }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);

    let filter = build_filter(&items, "test", Some("OuterConfig"));
    let names: Vec<&str> = filter.fields.iter().map(|field| field.name.as_str()).collect();
    assert!(names.contains(&"routes[].path"), "flattened exact path should render");
    assert!(
        names.contains(&"routes[].path_prefix"),
        "flattened prefix path should render"
    );
    assert!(
        !names.contains(&"routes[].path.path"),
        "flattened field should not add an extra segment"
    );
}

#[test]
fn flattened_enum_variant_fields_render_as_one_of() {
    let source = "
            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct OuterConfig { routes: Vec<RouteConfig> }
            #[derive(Debug, Deserialize)]
            struct RouteConfig { #[serde(flatten)] path: PathMatch, cluster: String }
            #[derive(Debug, Deserialize)]
            #[serde(untagged)]
            enum PathMatch { Exact { path: String }, Prefix { path_prefix: String } }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);

    let filter = build_filter(&items, "test", Some("OuterConfig"));
    let path_field = filter.fields.iter().find(|field| field.name == "routes[].path");
    let prefix_field = filter.fields.iter().find(|field| field.name == "routes[].path_prefix");

    assert_eq!(
        path_field.map(|field| field.required),
        Some(RequiredKind::OneOf),
        "flattened exact path should be marked as one-of"
    );
    assert_eq!(
        prefix_field.map(|field| field.required),
        Some(RequiredKind::OneOf),
        "flattened prefix path should be marked as one-of"
    );
}

#[test]
fn module_level_yaml_examples_are_included() {
    let source = "
            //! Module-level description.
            //!
            //! # YAML configuration
            //!
            //! ```yaml
            //! filter: module_filter
            //! answer: 42
            //! ```

            /// Public filter description.
            pub struct ModuleFilter;

            #[derive(Debug, Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ModuleConfig {
                /// Answer value.
                answer: u64,
            }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    let mut items = ModuleItems::new();
    parse_file_items(&file, &mut items);

    let filter = build_filter(&items, "module_filter", Some("ModuleConfig"));

    assert_eq!(
        filter.yaml_examples,
        vec!["filter: module_filter\nanswer: 42".to_owned()],
        "module-level YAML examples should be rendered"
    );
}

#[test]
fn render_reference_index_format() {
    let entries = vec![FilterEntry {
        protocol: "http".to_owned(),
        category: "traffic_management".to_owned(),
        required_feature: None,
        filter: FilterInfo {
            name: "timeout".to_owned(),
            description: "Enforces maximum latency.".to_owned(),
            extra_descriptions: vec![],
            config_notes: vec![],
            fields: vec![],
            yaml_examples: vec![],
            link_definitions: BTreeMap::new(),
        },
    }];
    let result = render_reference_index(&entries);
    assert!(result.contains("# Filter Reference"), "should have title");
    assert!(
        result.contains("## HTTP / Traffic Management"),
        "should have category heading"
    );
    assert!(
        result.contains("[`timeout`](http/traffic_management/timeout.md)"),
        "should have filter link"
    );
}

#[test]
fn render_reference_index_marks_required_feature() {
    let mut entry = sample_filter_entry();
    entry.required_feature = Some("cpex".to_owned());
    let result = render_reference_index(&[entry]);
    assert!(
        result.contains("| [`timeout`](http/traffic_management/timeout.md) | `cpex` |"),
        "reference index should expose feature-gated filters"
    );
}

#[test]
fn format_title_protocol_category() {
    assert_eq!(
        format_title("http/traffic_management"),
        "HTTP / Traffic Management",
        "should format protocol/category"
    );
    assert_eq!(format_title("http/ip"), "HTTP / IP", "should handle abbreviations");
    assert_eq!(
        format_title("tcp/traffic_management"),
        "TCP / Traffic Management",
        "should handle tcp"
    );
}

#[test]
fn has_from_config_detects_factory() {
    let source = "
            impl MyFilter {
                fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
                    Ok(Box::new(Self))
                }
            }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    if let syn::Item::Impl(imp) = &file.items[0] {
        assert!(has_from_config_method(imp), "should detect from_config method");
    } else {
        panic!("expected impl");
    }
}

#[test]
fn discover_feature_requirements_reads_registry_cfg() {
    let root = workspace_root();
    let registry = root.join("crates/filter/src/registry.rs");
    if !registry.is_file() {
        return;
    }
    let features = discover_feature_requirements(&root);
    assert!(
        !features.contains_key("router"),
        "unconditional registry entries should not be marked feature-gated"
    );
}

#[test]
fn extract_config_type_from_impl() {
    let source = r#"
            impl MyFilter {
                fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
                    let cfg: MyFilterConfig = parse_filter_config("my_filter", config)?;
                    Ok(Box::new(Self { timeout: cfg.timeout }))
                }
            }
        "#;
    let file: syn::File = syn::parse_str(source).unwrap();
    if let syn::Item::Impl(imp) = &file.items[0] {
        assert_eq!(
            extract_config_type_name(imp),
            Some("MyFilterConfig".to_owned()),
            "should extract config type name"
        );
    } else {
        panic!("expected impl");
    }
}

#[test]
fn extract_config_type_none_without_parse() {
    let source = "
            impl MyFilter {
                fn from_config(_config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
                    Ok(Box::new(Self))
                }
            }
        ";
    let file: syn::File = syn::parse_str(source).unwrap();
    if let syn::Item::Impl(imp) = &file.items[0] {
        assert_eq!(
            extract_config_type_name(imp),
            None,
            "should return None for config-less filters"
        );
    } else {
        panic!("expected impl");
    }
}

#[test]
fn extract_filters_from_real_codebase() {
    let root = workspace_root();
    let timeout_dir = root.join("crates/filter/src/builtins/http/traffic_management");
    if !timeout_dir.is_dir() {
        return;
    }
    let filters = extract_filters(&timeout_dir, &ModuleItems::new());
    assert!(
        !filters.is_empty(),
        "should extract at least one filter from traffic_management"
    );
    let timeout = filters.iter().find(|f| f.name == "timeout");
    assert!(timeout.is_some(), "should find timeout filter");
    let timeout = timeout.unwrap();
    assert!(!timeout.description.is_empty(), "timeout should have a description");
    assert!(!timeout.fields.is_empty(), "timeout should have at least one field");
    assert!(!timeout.yaml_examples.is_empty(), "timeout should have a yaml example");
}

#[test]
fn discover_anchors_finds_nested_filters() {
    let root = workspace_root();
    let pp_dir = root.join("crates/filter/src/builtins/http/payload_processing");
    if !pp_dir.is_dir() {
        return;
    }
    let anchors = discover_filter_anchors(&pp_dir);
    let names: Vec<&str> = anchors.iter().map(|a| a.name.as_str()).collect();

    assert!(
        names.contains(&"json_rpc"),
        "should find json_rpc in payload_processing/json_rpc/"
    );
}

#[test]
fn json_body_field_docs_include_one_of_note() {
    let root = workspace_root();
    let dir = root.join("crates/filter/src/builtins/http/payload_processing");
    if !dir.is_dir() {
        return;
    }
    let filters = extract_filters(&dir, &ModuleItems::new());
    let field = filters
        .iter()
        .find(|f| f.name == "json_body_field")
        .expect("json_body_field filter");
    assert!(
        field.config_notes.iter().any(|note| note.contains("single-field")),
        "one-of config note should be extracted"
    );
    assert!(
        field
            .fields
            .iter()
            .filter(|f| !f.name.contains('.') && !f.name.contains("[]"))
            .all(|f| f.name == "max_body_bytes" || f.required != RequiredKind::Yes),
        "one-of Option fields should be optional"
    );
}

#[test]
fn json_body_field_docs_include_specific_yaml_examples() {
    let root = workspace_root();
    let dir = root.join("crates/filter/src/builtins/http/payload_processing");
    if !dir.is_dir() {
        return;
    }
    let filters = extract_filters(&dir, &ModuleItems::new());
    let field = filters
        .iter()
        .find(|f| f.name == "json_body_field")
        .expect("json_body_field filter");
    assert!(
        field
            .yaml_examples
            .iter()
            .any(|example| example.contains("field: model")),
        "single-field YAML example should be extracted"
    );
    assert!(
        field.yaml_examples.iter().any(|example| example.contains("fields:")),
        "multi-field YAML example should be extracted"
    );
}

#[test]
fn static_response_uses_correct_config() {
    let root = workspace_root();
    let tm_dir = root.join("crates/filter/src/builtins/http/traffic_management");
    if !tm_dir.is_dir() {
        return;
    }
    let filters = extract_filters(&tm_dir, &ModuleItems::new());
    let sr = filters.iter().find(|f| f.name == "static_response");
    assert!(sr.is_some(), "should find static_response");
    let sr = sr.unwrap();
    let field_names: Vec<&str> = sr.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(
        field_names.contains(&"status"),
        "should have status field, not name/value from HeaderEntry"
    );
}

#[test]
fn numeric_types_render_language_neutral() {
    let enums = BTreeMap::new();
    let u64_ty: syn::Type = syn::parse_str("u64").unwrap();
    assert_eq!(render_type(&u64_ty, &enums), "integer", "unsigned integers");
    let usize_ty: syn::Type = syn::parse_str("usize").unwrap();
    assert_eq!(render_type(&usize_ty, &enums), "integer", "usize");
    let i32_ty: syn::Type = syn::parse_str("i32").unwrap();
    assert_eq!(render_type(&i32_ty, &enums), "integer", "signed integers");
    let f64_ty: syn::Type = syn::parse_str("f64").unwrap();
    assert_eq!(render_type(&f64_ty, &enums), "number", "floats");
}

// -------------------------------------------------------------------------
// Test Utilities
// -------------------------------------------------------------------------

/// Build a sample [`FilterEntry`] for rendering tests.
fn sample_filter_entry() -> FilterEntry {
    FilterEntry {
        protocol: "http".to_owned(),
        category: "traffic_management".to_owned(),
        required_feature: None,
        filter: FilterInfo {
            name: "timeout".to_owned(),
            description: "Enforces maximum latency.".to_owned(),
            extra_descriptions: vec![],
            config_notes: vec![],
            fields: vec![FieldInfo {
                name: "timeout_ms".to_owned(),
                type_str: "integer".to_owned(),
                doc: "Max time in milliseconds.".to_owned(),
                required: RequiredKind::Yes,
            }],
            yaml_examples: vec!["filter: timeout\ntimeout_ms: 5000".to_owned()],
            link_definitions: BTreeMap::new(),
        },
    }
}
