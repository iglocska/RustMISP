//! Manage MISP sharing groups: create, update, manage membership, and clean up.
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example sharing_groups
//! ```

use rustmisp::{MispClient, MispResult, MispSharingGroup};

#[tokio::main]
async fn main() -> MispResult<()> {
    // Read connection details from environment variables.
    let url = std::env::var("MISP_URL").expect("Set MISP_URL environment variable");
    let key = std::env::var("MISP_KEY").expect("Set MISP_KEY environment variable");
    let ssl_verify = std::env::var("MISP_SSL_VERIFY")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    // Build the client.
    let client = MispClient::new(&url, &key, ssl_verify)?;

    // Verify connectivity.
    let version = client.misp_instance_version().await?;
    println!("Connected to MISP {version}");

    // ── List existing sharing groups ────────────────────────────────────
    let groups = client.sharing_groups().await?;
    println!("Server has {} sharing group(s)", groups.len());

    // ── Create a new sharing group ──────────────────────────────────────
    let mut sg = MispSharingGroup::new("RustMISP Example SG");
    sg.description = Some("Sharing group created by the RustMISP example".into());
    sg.releasability = Some("TLP:AMBER".into());

    let created = client.add_sharing_group(&sg).await?;
    let sg_id = created.id.expect("server should assign an id");
    println!("Created sharing group #{sg_id}: {}", created.name);

    // ── Verify it exists ────────────────────────────────────────────────
    let exists = client.sharing_group_exists(sg_id).await?;
    println!("Sharing group #{sg_id} exists: {exists}");

    // ── Retrieve the sharing group ──────────────────────────────────────
    let fetched = client.get_sharing_group(sg_id).await?;
    println!(
        "Sharing group #{}: description={}, releasability={}, active={}",
        sg_id,
        fetched.description.as_deref().unwrap_or("(none)"),
        fetched.releasability.as_deref().unwrap_or("(none)"),
        fetched.active,
    );

    // ── Update the sharing group ────────────────────────────────────────
    let mut updated_sg = fetched;
    updated_sg.description = Some("Updated description from RustMISP".into());
    updated_sg.releasability = Some("TLP:GREEN".into());

    let updated = client.update_sharing_group(&updated_sg).await?;
    println!(
        "Updated sharing group #{sg_id}: releasability={}",
        updated.releasability.as_deref().unwrap_or("(none)"),
    );

    // ── Clean up: delete the sharing group ──────────────────────────────
    client.delete_sharing_group(sg_id).await?;
    println!("Deleted sharing group #{sg_id}");

    Ok(())
}
