//! multipart/form-data: parse a request body and build one for whisper-server.

#[derive(Debug, Default, Clone)]
pub struct Part {
    pub name: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

pub fn boundary(content_type: &str) -> Option<String> {
    content_type.split(';').map(str::trim).find_map(|item| {
        item.strip_prefix("boundary=")
            .map(|b| b.trim_matches('"').to_owned())
    })
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn disposition_value(header: &str, key: &str) -> Option<String> {
    header.split(';').map(str::trim).find_map(|item| {
        item.strip_prefix(&format!("{key}="))
            .map(|value| value.trim_matches('"').to_owned())
    })
}

pub fn parse(body: &[u8], boundary: &str) -> Result<Vec<Part>, String> {
    let delimiter = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut position = find(body, &delimiter, 0).ok_or("multipart boundary not found")?;
    loop {
        let mut start = position + delimiter.len();
        if body[start..].starts_with(b"--") {
            return Ok(parts);
        }
        if body[start..].starts_with(b"\r\n") {
            start += 2;
        }
        let header_end = find(body, b"\r\n\r\n", start).ok_or("multipart part has no header end")?;
        let headers = String::from_utf8_lossy(&body[start..header_end]).into_owned();
        let data_start = header_end + 4;
        let mut next_delimiter = b"\r\n".to_vec();
        next_delimiter.extend_from_slice(&delimiter);
        let data_end = find(body, &next_delimiter, data_start).ok_or("multipart part is not closed")?;
        let mut part = Part {
            data: body[data_start..data_end].to_vec(),
            ..Part::default()
        };
        for line in headers.split("\r\n") {
            let Some((name, value)) = line.split_once(':') else { continue };
            match name.trim().to_ascii_lowercase().as_str() {
                "content-disposition" => {
                    part.name = disposition_value(value, "name").unwrap_or_default();
                    part.filename = disposition_value(value, "filename");
                }
                "content-type" => part.content_type = Some(value.trim().to_owned()),
                _ => {}
            }
        }
        parts.push(part);
        position = data_end + 2;
    }
}

/// Build a multipart body. Returns the body and its boundary.
pub fn build(fields: &[(&str, String)], file: &Part) -> (Vec<u8>, String) {
    let boundary = format!("vexa-stt-{:x}", std::process::id() as u64 * 7919 + file.data.len() as u64);
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
        );
    }
    let filename = file.filename.clone().unwrap_or_else(|| "audio".to_owned());
    let content_type = file.content_type.clone().unwrap_or_else(|| "application/octet-stream".to_owned());
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(&file.data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (body, boundary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_fields_and_binary_file() {
        let file = Part {
            name: "file".into(),
            filename: Some("a.flac".into()),
            content_type: Some("audio/flac".into()),
            data: vec![0, 13, 10, 45, 45, 255],
        };
        let (body, boundary) = build(&[("model", "whisper-1".into()), ("language", "en".into())], &file);
        let parts = parse(&body, &boundary).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].name, "model");
        assert_eq!(parts[0].data, b"whisper-1");
        assert_eq!(parts[2].filename.as_deref(), Some("a.flac"));
        assert_eq!(parts[2].data, file.data);
    }

    #[test]
    fn reads_the_boundary_parameter() {
        assert_eq!(boundary("multipart/form-data; boundary=\"abc\"").as_deref(), Some("abc"));
        assert_eq!(boundary("multipart/form-data;boundary=x-1").as_deref(), Some("x-1"));
    }
}
