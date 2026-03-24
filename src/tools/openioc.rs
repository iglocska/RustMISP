//! OpenIOC format importer — converts OpenIOC XML to MISP attributes.

use std::fs;
use std::path::Path;

use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::error::{MispError, MispResult};
use crate::models::attribute::MispAttribute;
use crate::validation;

/// Mapping from OpenIOC indicator search terms to MISP attribute types.
fn openioc_to_misp_type(search: &str) -> Option<&'static str> {
    match search {
        "FileItem/Md5sum" => Some("md5"),
        "FileItem/Sha1sum" => Some("sha1"),
        "FileItem/Sha256sum" => Some("sha256"),
        "FileItem/FileName" | "FileItem/PEInfo/OriginalFileName" => Some("filename"),
        "FileItem/FullPath" | "FileItem/FilePath" => Some("filename"),
        "FileItem/SizeInBytes" => Some("size-in-bytes"),
        "FileItem/PEInfo/DetectedAnomalies/string" => Some("pattern-in-file"),
        "Network/DNS" | "DnsEntryItem/RecordName" | "DnsEntryItem/Host" => Some("domain"),
        "PortItem/remoteIP" | "Network/RemoteIP" => Some("ip-dst"),
        "PortItem/localIP" | "Network/LocalIP" => Some("ip-src"),
        "RouteEntryItem/Destination" => Some("ip-dst"),
        "Network/URI" | "UrlHistoryItem/URL" => Some("url"),
        "Network/UserAgent" => Some("user-agent"),
        "Email/From" => Some("email-src"),
        "Email/To" => Some("email-dst"),
        "Email/Subject" => Some("email-subject"),
        "RegistryItem/Path" | "RegistryItem/KeyPath" => Some("regkey"),
        "RegistryItem/ValueName" => Some("regkey"),
        "ProcessItem/name" | "ServiceItem/name" => Some("pattern-in-memory"),
        "ProcessItem/arguments" => Some("pattern-in-memory"),
        "Snort/Snort" => Some("snort"),
        "Yara/Yara" => Some("yara"),
        _ => None,
    }
}

/// Load MISP attributes from an OpenIOC XML string.
pub fn load_openioc(xml_content: &str) -> MispResult<Vec<MispAttribute>> {
    let mut reader = Reader::from_str(xml_content);

    let mut attributes = Vec::new();
    let mut current_search: Option<String> = None;
    let mut in_content = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e) | Event::Empty(ref e)) => {
                let local_name = e.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");

                if name == "IndicatorItem" {
                    current_search = None;
                } else if name == "Context" {
                    // Extract the "search" attribute
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"search" {
                            current_search = Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                } else if name == "Content" {
                    in_content = true;
                }
            }
            Ok(Event::Text(ref e)) if in_content => {
                if let Some(ref search) = current_search {
                    let value = e.unescape().unwrap_or_default().trim().to_string();
                    if !value.is_empty() {
                        if let Some(misp_type) = openioc_to_misp_type(search) {
                            let category =
                                validation::get_default_category(misp_type).unwrap_or("Other");
                            let to_ids = validation::get_default_to_ids(misp_type).unwrap_or(true);

                            let mut attr = MispAttribute::new(misp_type, category, &value);
                            attr.to_ids = to_ids;
                            attr.comment = format!("OpenIOC: {search}");
                            attributes.push(attr);
                        }
                    }
                }
                in_content = false;
            }
            Ok(Event::End(ref e)) => {
                let local_name = e.local_name();
                let name = std::str::from_utf8(local_name.as_ref()).unwrap_or("");
                if name == "Content" {
                    in_content = false;
                } else if name == "IndicatorItem" {
                    current_search = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(MispError::InvalidInput(format!(
                    "OpenIOC XML parse error: {e}"
                )));
            }
            _ => {}
        }
    }

    Ok(attributes)
}

/// Load MISP attributes from an OpenIOC XML file.
pub fn load_openioc_file(path: impl AsRef<Path>) -> MispResult<Vec<MispAttribute>> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| {
        MispError::InvalidInput(format!(
            "Failed to read OpenIOC file {}: {}",
            path.as_ref().display(),
            e
        ))
    })?;
    load_openioc(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openioc_basic_parse() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<ioc xmlns="http://schemas.mandiant.com/2010/ioc">
  <definition>
    <Indicator operator="OR">
      <IndicatorItem>
        <Context document="FileItem" search="FileItem/Md5sum" type="mir"/>
        <Content type="md5">d41d8cd98f00b204e9800998ecf8427e</Content>
      </IndicatorItem>
      <IndicatorItem>
        <Context document="FileItem" search="FileItem/FileName" type="mir"/>
        <Content type="string">malware.exe</Content>
      </IndicatorItem>
      <IndicatorItem>
        <Context document="Network" search="Network/DNS" type="mir"/>
        <Content type="string">evil.example.com</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>"#;

        let attrs = load_openioc(xml).unwrap();
        assert_eq!(attrs.len(), 3);

        assert_eq!(attrs[0].attr_type, "md5");
        assert_eq!(attrs[0].value, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(attrs[0].category, "Payload delivery");

        assert_eq!(attrs[1].attr_type, "filename");
        assert_eq!(attrs[1].value, "malware.exe");

        assert_eq!(attrs[2].attr_type, "domain");
        assert_eq!(attrs[2].value, "evil.example.com");
        assert_eq!(attrs[2].category, "Network activity");
    }

    #[test]
    fn openioc_empty_content_skipped() {
        let xml = r#"<?xml version="1.0"?>
<ioc>
  <definition>
    <Indicator operator="OR">
      <IndicatorItem>
        <Context search="FileItem/Md5sum"/>
        <Content type="md5">   </Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>"#;
        let attrs = load_openioc(xml).unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn openioc_unknown_search_ignored() {
        let xml = r#"<?xml version="1.0"?>
<ioc>
  <definition>
    <Indicator operator="OR">
      <IndicatorItem>
        <Context search="UnknownItem/Field"/>
        <Content type="string">somevalue</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>"#;
        let attrs = load_openioc(xml).unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn openioc_ip_addresses() {
        let xml = r#"<?xml version="1.0"?>
<ioc>
  <definition>
    <Indicator operator="OR">
      <IndicatorItem>
        <Context search="PortItem/remoteIP"/>
        <Content type="IP">10.0.0.1</Content>
      </IndicatorItem>
    </Indicator>
  </definition>
</ioc>"#;
        let attrs = load_openioc(xml).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].attr_type, "ip-dst");
        assert_eq!(attrs[0].value, "10.0.0.1");
    }
}
