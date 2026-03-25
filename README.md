# RustMISP

[![CI](https://github.com/iglocska/RustMISP/actions/workflows/ci.yml/badge.svg)](https://github.com/iglocska/RustMISP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![PyMISP API parity](https://img.shields.io/badge/PyMISP_API_parity-99.5%25-brightgreen.svg)](scripts/check_pymisp_parity.py)
[![PyMISP test parity](https://img.shields.io/badge/PyMISP_test_parity-78.8%25-yellow.svg)](scripts/check_pymisp_parity.py)

A Rust client library for the [MISP](https://www.misp-project.org/) REST API, providing feature parity with [PyMISP](https://github.com/MISP/PyMISP).

RustMISP offers strongly-typed data models for 30+ MISP entity types, an ergonomic async API client with ~243 methods, and an optional blocking wrapper.

## Quick start

Add RustMISP to your project:

```bash
cargo add rustmisp
```

### Async (default)

```rust
use rustmisp::{MispClient, MispEvent, MispAttribute, Distribution, MispResult};

#[tokio::main]
async fn main() -> MispResult<()> {
    let client = MispClient::new("https://misp.example.com", "your-api-key", false)?;

    // Check connectivity
    let version = client.misp_instance_version().await?;
    println!("Connected to MISP {version}");

    // Create an event
    let mut event = MispEvent::new("Suspicious phishing campaign");
    event.distribution = Some(Distribution::YourOrganisationOnly as i64);
    let created = client.add_event(&event).await?;
    let event_id = created.id.unwrap();

    // Add an indicator
    let attr = MispAttribute::new("ip-dst", "Network activity", "198.51.100.42");
    client.add_attribute(event_id, &attr).await?;

    // Publish
    client.publish(event_id, false).await?;

    Ok(())
}
```

### Blocking

Enable the `blocking` feature for synchronous usage:

```toml
[dependencies]
rustmisp = { version = "0.1", features = ["blocking"] }
```

```rust
use rustmisp::{MispClientBlocking, MispResult};

fn main() -> MispResult<()> {
    let client = MispClientBlocking::new("https://misp.example.com", "your-api-key", false)?;
    let events = client.events()?;
    println!("Found {} events", events.len());
    Ok(())
}
```

## Features

| Feature | Description | Extra dependencies |
|---|---|---|
| `blocking` | Synchronous `MispClientBlocking` wrapper | — |
| `tools-file` | File hashing and MISP object generation | `sha2`, `md-5`, `sha1` |
| `tools-csv` | CSV-to-attribute import | `csv` |
| `tools-openioc` | OpenIOC XML import | `quick-xml` |
| `tools-feed` | Feed metadata generation | — |
| `tools-all` | Enables all tool features | all of the above |

## API coverage

RustMISP covers the full MISP REST API surface:

- **Events** — CRUD, publish/unpublish, contact reporter, enrich
- **Attributes** — CRUD, restore, enrich, freetext import
- **Objects** — CRUD with templates and references
- **Tags** — CRUD, attach/detach, search, enable/disable
- **Proposals** — shadow attribute workflow (add, accept, discard)
- **Sightings** — add, list, delete, search
- **Taxonomies** — list, enable/disable, toggle required
- **Warninglists** — list, toggle, check values
- **Galaxies & clusters** — CRUD, attach, fork, publish, relations
- **Organisations, users, roles** — admin CRUD, registration workflow
- **Servers** — sync config, pull/push, worker management
- **Feeds** — CRUD, fetch, cache, compare
- **Sharing groups** — CRUD, add/remove orgs and servers
- **Search** — `SearchBuilder` with 50+ parameters, complex queries, multiple return formats
- **Blocklists, communities, delegations, logs, user settings, correlation exclusions, decaying models, noticelists, event reports**

## Client configuration

Use `MispClientBuilder` for advanced configuration:

```rust
use rustmisp::MispClientBuilder;
use std::time::Duration;

let client = MispClientBuilder::new("https://misp.example.com", "your-api-key")
    .ssl(false)
    .timeout(Duration::from_secs(60))
    .proxy("http://proxy.example.com:8080")
    .build()?;
```

## Search

The `SearchBuilder` provides a fluent API for constructing search queries:

```rust
use rustmisp::{SearchBuilder, SearchController, ReturnFormat};

let params = SearchBuilder::new()
    .controller(SearchController::Attributes)
    .type_attribute("ip-dst")
    .tags(&["tlp:white"])
    .published(true)
    .limit(100)
    .return_format(ReturnFormat::Json)
    .build();

let results = client.search(SearchController::Attributes, &params).await?;
```

## Documentation

For a complete API reference covering all 140+ methods with examples, see [`docs.md`](docs.md).

## Examples

See the [`examples/`](examples/) directory:

```bash
# Set connection details
export MISP_URL=https://misp.example.com
export MISP_KEY=your-api-key

# Run an example
cargo run --example basic_event
cargo run --example search_attributes
cargo run --example manage_tags
cargo run --example feed_operations
cargo run --example user_management
cargo run --example galaxy_operations
cargo run --example sightings
cargo run --example sharing_groups
```

## Minimum supported Rust version

Rust 1.85 or later.

## License

MIT — see [LICENSE](LICENSE).
