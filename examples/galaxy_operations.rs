//! Browse, search, and manage MISP galaxies and galaxy clusters.
//!
//! Demonstrates listing galaxies, viewing clusters, creating custom clusters,
//! attaching clusters to events, and managing cluster relations.
//!
//! # Usage
//!
//! ```bash
//! MISP_URL=https://misp.example.com MISP_KEY=your-api-key cargo run --example galaxy_operations
//! ```

use rustmisp::{
    Analysis, Distribution, MispClient, MispEvent, MispGalaxyCluster,
    MispGalaxyClusterRelation, MispResult, ThreatLevel,
};

#[tokio::main]
async fn main() -> MispResult<()> {
    let url = std::env::var("MISP_URL").expect("Set MISP_URL environment variable");
    let key = std::env::var("MISP_KEY").expect("Set MISP_KEY environment variable");
    let ssl_verify = std::env::var("MISP_SSL_VERIFY")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(true);

    let client = MispClient::new(&url, &key, ssl_verify)?;

    // ── 1. List available galaxies ────────────────────────────────────────────
    let galaxies = client.galaxies(false).await?;
    println!("=== Available galaxies: {} total ===", galaxies.len());
    for galaxy in galaxies.iter().take(5) {
        println!(
            "  #{}: {} (type: {})",
            galaxy.id.unwrap_or(0),
            galaxy.name,
            galaxy.galaxy_type.as_deref().unwrap_or("unknown")
        );
    }
    if galaxies.len() > 5 {
        println!("  ... and {} more", galaxies.len() - 5);
    }

    // ── 2. Search for a galaxy by keyword ─────────────────────────────────────
    let results = client.search_galaxy("threat-actor").await?;
    println!("\n=== Search for 'threat-actor' ===");
    println!("{results}");

    // ── 3. View a galaxy with its clusters ────────────────────────────────────
    // Use the first galaxy from the list.
    let first_galaxy_id = galaxies
        .first()
        .and_then(|g| g.id)
        .expect("at least one galaxy must exist");

    let galaxy = client.get_galaxy(first_galaxy_id, true).await?;
    println!(
        "\n=== Galaxy '{}' has {} cluster(s) ===",
        galaxy.name,
        galaxy.galaxy_clusters.len()
    );
    for cluster in galaxy.galaxy_clusters.iter().take(3) {
        println!(
            "  #{}: {} (tag: {})",
            cluster.id.unwrap_or(0),
            cluster.value,
            cluster.tag_name.as_deref().unwrap_or("none")
        );
    }
    if galaxy.galaxy_clusters.len() > 3 {
        println!("  ... and {} more", galaxy.galaxy_clusters.len() - 3);
    }

    // ── 4. Create a custom galaxy cluster ─────────────────────────────────────
    let mut custom_cluster = MispGalaxyCluster::new("RustMISP Example Cluster");
    custom_cluster.description = Some("A test cluster created by the galaxy_operations example".into());
    custom_cluster.source = Some("RustMISP".into());
    custom_cluster.authors = Some(vec!["RustMISP Example".into()]);
    custom_cluster.distribution = Some(Distribution::YourOrganisationOnly as i64);

    let created_cluster = client
        .add_galaxy_cluster(first_galaxy_id, &custom_cluster)
        .await?;
    let cluster_id = created_cluster.id.expect("server should assign an id");
    let cluster_uuid = created_cluster
        .uuid
        .clone()
        .expect("server should assign a uuid");
    println!("\nCreated cluster #{cluster_id}: {}", created_cluster.value);

    // ── 5. Update the cluster ─────────────────────────────────────────────────
    let mut updated_cluster = created_cluster.clone();
    updated_cluster.description = Some("Updated description from RustMISP".into());
    let updated_cluster = client.update_galaxy_cluster(&updated_cluster).await?;
    println!(
        "Updated cluster description: {}",
        updated_cluster
            .description
            .as_deref()
            .unwrap_or("(none)")
    );

    // ── 6. Fetch the cluster by ID ────────────────────────────────────────────
    let fetched = client.get_galaxy_cluster(cluster_id).await?;
    println!(
        "\nFetched cluster #{}: {} (published: {})",
        fetched.id.unwrap_or(0),
        fetched.value,
        fetched.published
    );

    // ── 7. Attach a galaxy cluster to an event ────────────────────────────────
    // Create a temporary event to demonstrate attachment.
    let mut event = MispEvent::new("RustMISP galaxy operations example");
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

    client
        .attach_galaxy_cluster(event_uuid, &cluster_uuid, false)
        .await?;
    println!("Attached cluster '{}' to event", fetched.value);

    // ── 8. Search galaxy clusters ─────────────────────────────────────────────
    let search_results = client
        .search_galaxy_clusters(
            &first_galaxy_id.to_string(),
            Some("all"),
            false,
        )
        .await?;
    println!("\n=== Galaxy cluster search results ===");
    println!("{search_results}");

    // ── 9. Create a cluster relation ──────────────────────────────────────────
    // Create a second cluster to relate to the first.
    let mut related_cluster = MispGalaxyCluster::new("RustMISP Related Cluster");
    related_cluster.description = Some("Related cluster for demonstrating relations".into());
    related_cluster.distribution = Some(Distribution::YourOrganisationOnly as i64);

    let related = client
        .add_galaxy_cluster(first_galaxy_id, &related_cluster)
        .await?;
    let related_id = related.id.expect("server should assign an id");
    let related_uuid = related.uuid.clone().expect("server should assign a uuid");
    println!("\nCreated related cluster #{related_id}: {}", related.value);

    let mut relation =
        MispGalaxyClusterRelation::new(&related_uuid, "related-to");
    relation.galaxy_cluster_id = Some(cluster_id);
    let created_relation = client.add_galaxy_cluster_relation(&relation).await?;
    let relation_id = created_relation
        .id
        .expect("server should assign a relation id");
    println!(
        "Created relation #{relation_id}: cluster #{cluster_id} --[related-to]--> #{related_id}"
    );

    // ── 10. Clean up ──────────────────────────────────────────────────────────
    client.delete_galaxy_cluster_relation(relation_id).await?;
    println!("\nDeleted relation #{relation_id}");

    client.delete_event(event_id).await?;
    println!("Deleted temporary event #{event_id}");

    client.delete_galaxy_cluster(cluster_id, true).await?;
    println!("Deleted cluster #{cluster_id}");

    client.delete_galaxy_cluster(related_id, true).await?;
    println!("Deleted related cluster #{related_id}");

    println!("\nDone!");
    Ok(())
}
