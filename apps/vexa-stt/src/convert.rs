//! Convert a whisper.cpp `verbose_json` answer into the Vexa transcription
//! response (the shape `core/meetings/services/transcription` returns).

use crate::json::{object, Value};

/// The silence rule of the Python service (`_looks_like_silence`).
pub const NO_SPEECH_THRESHOLD: f64 = 0.6;
pub const LOG_PROB_THRESHOLD: f64 = -1.0;

/// Whisper's language codes and the names whisper.cpp prints.
const LANGUAGES: [(&str, &str); 100] = [
    ("en", "english"), ("zh", "chinese"), ("de", "german"), ("es", "spanish"), ("ru", "russian"),
    ("ko", "korean"), ("fr", "french"), ("ja", "japanese"), ("pt", "portuguese"), ("tr", "turkish"),
    ("pl", "polish"), ("ca", "catalan"), ("nl", "dutch"), ("ar", "arabic"), ("sv", "swedish"),
    ("it", "italian"), ("id", "indonesian"), ("hi", "hindi"), ("fi", "finnish"), ("vi", "vietnamese"),
    ("he", "hebrew"), ("uk", "ukrainian"), ("el", "greek"), ("ms", "malay"), ("cs", "czech"),
    ("ro", "romanian"), ("da", "danish"), ("hu", "hungarian"), ("ta", "tamil"), ("no", "norwegian"),
    ("th", "thai"), ("ur", "urdu"), ("hr", "croatian"), ("bg", "bulgarian"), ("lt", "lithuanian"),
    ("la", "latin"), ("mi", "maori"), ("ml", "malayalam"), ("cy", "welsh"), ("sk", "slovak"),
    ("te", "telugu"), ("fa", "persian"), ("lv", "latvian"), ("bn", "bengali"), ("sr", "serbian"),
    ("az", "azerbaijani"), ("sl", "slovenian"), ("kn", "kannada"), ("et", "estonian"), ("mk", "macedonian"),
    ("br", "breton"), ("eu", "basque"), ("is", "icelandic"), ("hy", "armenian"), ("ne", "nepali"),
    ("mn", "mongolian"), ("bs", "bosnian"), ("kk", "kazakh"), ("sq", "albanian"), ("sw", "swahili"),
    ("gl", "galician"), ("mr", "marathi"), ("pa", "punjabi"), ("si", "sinhala"), ("km", "khmer"),
    ("sn", "shona"), ("yo", "yoruba"), ("so", "somali"), ("af", "afrikaans"), ("oc", "occitan"),
    ("ka", "georgian"), ("be", "belarusian"), ("tg", "tajik"), ("sd", "sindhi"), ("gu", "gujarati"),
    ("am", "amharic"), ("yi", "yiddish"), ("lo", "lao"), ("uz", "uzbek"), ("fo", "faroese"),
    ("ht", "haitian creole"), ("ps", "pashto"), ("tk", "turkmen"), ("nn", "nynorsk"), ("mt", "maltese"),
    ("sa", "sanskrit"), ("lb", "luxembourgish"), ("my", "myanmar"), ("bo", "tibetan"), ("tl", "tagalog"),
    ("mg", "malagasy"), ("as", "assamese"), ("tt", "tatar"), ("haw", "hawaiian"), ("ln", "lingala"),
    ("ha", "hausa"), ("ba", "bashkir"), ("jw", "javanese"), ("su", "sundanese"), ("yue", "cantonese"),
];

/// A language code from a whisper.cpp name or code ("english" → "en").
pub fn language_code(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    LANGUAGES
        .iter()
        .find(|(code, full)| *full == lower || *code == lower)
        .map_or(lower, |(code, _)| (*code).to_owned())
}

/// faster-whisper's `compression_ratio`: UTF-8 length over zlib length.
pub fn compression_ratio(text: &str) -> f64 {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(bytes, 6);
    bytes.len() as f64 / compressed.len() as f64
}

fn num(value: Option<&Value>) -> f64 {
    value.and_then(Value::as_f64).unwrap_or(0.0)
}

pub struct Request<'a> {
    /// The language the caller asked for, if any.
    pub language: Option<&'a str>,
    pub temperature: f64,
    pub want_words: bool,
}

pub fn convert(whisper: &Value, request: &Request) -> Value {
    let raw_segments = whisper.get("segments").and_then(Value::as_array).unwrap_or(&[]);
    let mut segments = Vec::new();
    for (index, raw) in raw_segments.iter().enumerate() {
        let text = raw.get("text").and_then(Value::as_str).unwrap_or("").to_owned();
        let start = num(raw.get("start"));
        let end = num(raw.get("end"));
        let mut items = vec![
            ("id", Value::Number(index as f64)),
            ("seek", Value::Number(0.0)),
            ("start", Value::Number(start)),
            ("end", Value::Number(end)),
            ("text", Value::String(text.clone())),
            ("tokens", Value::Array(Vec::new())),
            (
                "temperature",
                Value::Number(raw.get("temperature").and_then(Value::as_f64).unwrap_or(request.temperature)),
            ),
            ("avg_logprob", Value::Number(num(raw.get("avg_logprob")))),
            ("compression_ratio", Value::Number(compression_ratio(&text))),
            ("no_speech_prob", Value::Number(num(raw.get("no_speech_prob")))),
            ("audio_start", Value::Number(start)),
            ("audio_end", Value::Number(end)),
        ];
        if request.want_words {
            if let Some(words) = raw.get("words").and_then(Value::as_array) {
                if !words.is_empty() {
                    let words = words
                        .iter()
                        .map(|w| {
                            object(vec![
                                ("word", Value::String(w.get("word").and_then(Value::as_str).unwrap_or("").to_owned())),
                                ("start", Value::Number(num(w.get("start")))),
                                ("end", Value::Number(num(w.get("end")))),
                                ("probability", Value::Number(num(w.get("probability")))),
                            ])
                        })
                        .collect();
                    items.push(("words", Value::Array(words)));
                }
            }
        }
        segments.push(object(items));
    }

    let (language, probability) = match request.language.filter(|l| !l.is_empty() && *l != "auto") {
        // faster-whisper reports probability 1 for a language the caller set.
        Some(language) => (language_code(language), 1.0),
        None => (
            language_code(
                whisper
                    .get("detected_language")
                    .or_else(|| whisper.get("language"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
            ),
            num(whisper.get("detected_language_probability")),
        ),
    };

    let silent = segments.iter().all(|s| {
        num(s.get("no_speech_prob")) > NO_SPEECH_THRESHOLD && num(s.get("avg_logprob")) < LOG_PROB_THRESHOLD
    });
    if silent {
        return object(vec![
            ("text", Value::String(String::new())),
            ("language", Value::String(language)),
            ("language_probability", Value::Number(probability)),
            ("duration", Value::Number(0.0)),
            ("segments", Value::Array(Vec::new())),
        ]);
    }
    let text = segments
        .iter()
        .map(|s| s.get("text").and_then(Value::as_str).unwrap_or("").trim().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_owned();
    let duration = segments.last().map_or(0.0, |s| num(s.get("end")));
    object(vec![
        ("text", Value::String(text)),
        ("language", Value::String(language)),
        ("language_probability", Value::Number(probability)),
        ("duration", Value::Number(duration)),
        ("segments", Value::Array(segments)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    const SAMPLE: &str = r#"{"task":"transcribe","language":"english","duration":3.48,
      "text":" Hello team, the review is at 10 o'\nclock.\n",
      "segments":[
        {"id":0,"text":" Hello team, the review is at 10 o'","start":0.0,"end":3.11,"tokens":[1],
         "words":[{"word":" Hello","start":0.05,"end":0.26,"t_dtw":-1,"probability":0.91}],
         "temperature":0.0,"avg_logprob":-0.07,"no_speech_prob":0.002},
        {"id":1,"text":"clock.","start":3.11,"end":3.4,"tokens":[2],"words":[],
         "temperature":0.0,"avg_logprob":-0.3,"no_speech_prob":0.01}],
      "detected_language":"english","detected_language_probability":0.97}"#;

    #[test]
    fn maps_whisper_cpp_output_to_the_vexa_shape() {
        let out = convert(&parse(SAMPLE).unwrap(), &Request { language: None, temperature: 0.0, want_words: true });
        assert_eq!(out.get("text").unwrap().as_str().unwrap(), "Hello team, the review is at 10 o' clock.");
        assert_eq!(out.get("language").unwrap().as_str().unwrap(), "en");
        assert_eq!(out.get("language_probability").unwrap().as_f64().unwrap(), 0.97);
        assert_eq!(out.get("duration").unwrap().as_f64().unwrap(), 3.4);
        let seg = &out.get("segments").unwrap().as_array().unwrap()[0];
        for key in ["id", "seek", "start", "end", "text", "tokens", "temperature", "avg_logprob", "compression_ratio", "no_speech_prob", "audio_start", "audio_end", "words"] {
            assert!(seg.get(key).is_some(), "segment lacks {key}");
        }
        let word = &seg.get("words").unwrap().as_array().unwrap()[0];
        assert!(word.get("t_dtw").is_none());
        assert_eq!(word.get("probability").unwrap().as_f64().unwrap(), 0.91);
        // An empty word list is left out, as faster-whisper does.
        assert!(out.get("segments").unwrap().as_array().unwrap()[1].get("words").is_none());
    }

    #[test]
    fn requested_language_has_probability_one_and_words_are_optional() {
        let out = convert(&parse(SAMPLE).unwrap(), &Request { language: Some("de"), temperature: 0.0, want_words: false });
        assert_eq!(out.get("language").unwrap().as_str().unwrap(), "de");
        assert_eq!(out.get("language_probability").unwrap().as_f64().unwrap(), 1.0);
        assert!(out.get("segments").unwrap().as_array().unwrap()[0].get("words").is_none());
    }

    #[test]
    fn silence_returns_empty_text() {
        let silent = r#"{"segments":[{"text":" you","start":0,"end":1,"avg_logprob":-1.5,"no_speech_prob":0.9}],"detected_language":"english"}"#;
        let out = convert(&parse(silent).unwrap(), &Request { language: None, temperature: 0.0, want_words: true });
        assert_eq!(out.get("text").unwrap().as_str().unwrap(), "");
        assert!(out.get("segments").unwrap().as_array().unwrap().is_empty());
        let none = convert(&parse(r#"{"segments":[]}"#).unwrap(), &Request { language: None, temperature: 0.0, want_words: false });
        assert_eq!(none.get("text").unwrap().as_str().unwrap(), "");
    }

    #[test]
    fn compression_ratio_matches_python_zlib() {
        // Python: len(b) / len(zlib.compress(b)) for b"hello hello hello hello" = 23 / 16
        let ratio = compression_ratio("hello hello hello hello");
        assert!((ratio - 23.0 / 16.0).abs() < 1e-9, "{ratio}");
    }
}
