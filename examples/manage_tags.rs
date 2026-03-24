//! Create, search, attach, and manage MISP tags.
//!
//! Demonstrates tag CRUD, searching, attaching tags to events and attributes,
//! and enabling/disabling tags.
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example manage_tags
//! ```

use rustmisp::{
    Analysis, Distribution, MispAttribute, MispClient, MispEvent, MispResult, MispTag,
    ThreatLevel,
};

#[tokio::main]
async fn main() -> MispResult<()> {
    let url = std::env::var("MISP_URL").expect("Set MISP_URL environment variable");
    let key = std::env::var("MISP_KEY").expect("Set MISP_KEY environment variable");
    let ssl_verify = std::env::var("MISP_SSL_VERIFY")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let client = MispClient::new(&url, &key, ssl_verify)?;

    // ── 1. List existing tags ────────────────────────────────────────────────
    let all_tags = client.tags().await?;
    println!("=== Existing tags: {} total ===", all_tags.len());
    for tag in all_tags.iter().take(5) {
        println!(
            "  #{}: {} (colour: {})",
            tag.id.unwrap_or(0),
            tag.name,
            tag.colour.as_deref().unwrap_or("none")
        );
    }
    if all_tags.len() > 5 {
        println!("  ... and {} more", all_tags.len() - 5);
    }

    // ── 2. Create a custom tag ───────────────────────────────────────────────
    let mut custom_tag = MispTag::new("rustmisp:example-tag");
    custom_tag.colour = Some("#3498db".into());
    custom_tag.exportable = true;

    let created_tag = client.add_tag(&custom_tag).await?;
    let tag_id = created_tag.id.expect("server should assign an id");
    println!("\nCreated tag #{tag_id}: {}", created_tag.name);

    // ── 3. Search for tags by name ───────────────────────────────────────────
    let found = client.search_tags("rustmisp", false).await?;
    println!("\n=== Search for 'rustmisp': {} result(s) ===", found.len());
    for tag in &found {
        println!("  {}", tag.name);
    }

    // ── 4. Update the tag ────────────────────────────────────────────────────
    let mut updated = created_tag.clone();
    updated.colour = Some("#e74c3c".into());
    let updated = client.update_tag(&updated).await?;
    println!(
        "\nUpdated tag colour to {}",
        updated.colour.as_deref().unwrap_or("none")
    );

    // ── 5. Disable and re-enable the tag ─────────────────────────────────────
    client.disable_tag(tag_id).await?;
    println!("Disabled tag #{tag_id}");

    client.enable_tag(tag_id).await?;
    println!("Re-enabled tag #{tag_id}");

    // ── 6. Attach tags to an event and an attribute ──────────────────────────
    // Create a temporary event to demonstrate tagging.
    let mut event = MispEvent::new("RustMISP tag management example");
    event.distribution = Some(Distribution::YourOrganisationOnly as i64);
    event.threat_level_id = Some(ThreatLevel::Low as i64);
    event.analysis = Some(Analysis::Initial as i64);

    let created_event = client.add_event(&event).await?;
    let event_id = created_event.id.expect("server should assign an id");
    let event_uuid = created_event
        .uuid
        .as_deref()
        .expect("server should assign a uuid");
    println!("\nCreated temporary event #{event_id}");

    // Tag the event.
    client.tag(event_uuid, "rustmisp:example-tag", false).await?;
    client.tag(event_uuid, "tlp:green", false).await?;
    println!("Tagged event with rustmisp:example-tag and tlp:green");

    // Add an attribute and tag it.
    let attr = MispAttribute::new("domain", "Network activity", "example.com");
    let created_attr = client.add_attribute(event_id, &attr).await?;
    let attr_uuid = created_attr
        .uuid
        .as_deref()
        .expect("server should assign a uuid");
    client.tag(attr_uuid, "rustmisp:example-tag", true).await?;
    println!("Tagged attribute with rustmisp:example-tag (local)");

    // ── 7. Verify tags were attached ─────────────────────────────────────────
    let fetched = client.get_event(event_id).await?;
    println!(
        "\nEvent #{event_id} has {} tag(s):",
        fetched.tags.len()
    );
    for tag in &fetched.tags {
        println!("  - {}", tag.name);
    }

    // ── 8. Remove a tag from the event ───────────────────────────────────────
    client.untag(event_uuid, "tlp:green").await?;
    println!("\nRemoved tlp:green from event");

    let fetched = client.get_event(event_id).await?;
    println!(
        "Event #{event_id} now has {} tag(s):",
        fetched.tags.len()
    );
    for tag in &fetched.tags {
        println!("  - {}", tag.name);
    }

    // ── 9. Clean up ──────────────────────────────────────────────────────────
    client.delete_event(event_id).await?;
    println!("\nDeleted temporary event #{event_id}");

    client.delete_tag(tag_id).await?;
    println!("Deleted custom tag #{tag_id}");

    Ok(())
}
