use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use uuid::Uuid;

pub(crate) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_ID_BYTES: usize = 64;
const MAX_VERSION_BYTES: usize = 128;
const MAX_NAME_BYTES: usize = 255;
const MAX_METHOD_BYTES: usize = 64;
const MAX_DIAGNOSTIC_BYTES: usize = 1024;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ServerHello {
    pub(crate) protocol_min: u32,
    pub(crate) protocol_max: u32,
    pub(crate) styrn_version: String,
    pub(crate) machine_id: Uuid,
    pub(crate) name: String,
    pub(crate) manifest_schema_version: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ClientHello {
    pub(crate) protocol: u32,
    pub(crate) styrn_version: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct RpcDiagnostic {
    pub(crate) code: String,
    pub(crate) message: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_diagnostic_details"
    )]
    pub(crate) details: Option<Value>,
}

fn deserialize_diagnostic_details<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let details = Value::deserialize(deserializer)?;
    if details.is_object() {
        Ok(Some(details))
    } else {
        Err(de::Error::custom(
            "RPC diagnostic details must be an object",
        ))
    }
}

impl RpcDiagnostic {
    pub(crate) fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_owned(),
            message: message.to_owned(),
            details: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Frame {
    ServerHello(ServerHello),
    ClientHello(ClientHello),
    Request {
        id: String,
        method: String,
        params: Value,
    },
    Response {
        id: String,
        ok: bool,
        data: Option<Value>,
        errors: Vec<RpcDiagnostic>,
    },
    Error {
        id: String,
        errors: Vec<RpcDiagnostic>,
    },
}

impl Serialize for Frame {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        match self {
            Self::ServerHello(hello) => {
                let mut state = serializer.serialize_struct("Frame", 8)?;
                state.serialize_field("id", "hello")?;
                state.serialize_field("type", "hello")?;
                state.serialize_field("protocol_min", &hello.protocol_min)?;
                state.serialize_field("protocol_max", &hello.protocol_max)?;
                state.serialize_field("styrn_version", &hello.styrn_version)?;
                state.serialize_field("machine_id", &hello.machine_id)?;
                state.serialize_field("name", &hello.name)?;
                state.serialize_field("manifest_schema_version", &hello.manifest_schema_version)?;
                state.end()
            }
            Self::ClientHello(hello) => {
                let mut state = serializer.serialize_struct("Frame", 4)?;
                state.serialize_field("id", "hello")?;
                state.serialize_field("type", "hello")?;
                state.serialize_field("protocol", &hello.protocol)?;
                state.serialize_field("styrn_version", &hello.styrn_version)?;
                state.end()
            }
            Self::Request { id, method, params } => {
                let mut state = serializer.serialize_struct("Frame", 4)?;
                state.serialize_field("id", id)?;
                state.serialize_field("type", "request")?;
                state.serialize_field("method", method)?;
                state.serialize_field("params", params)?;
                state.end()
            }
            Self::Response {
                id,
                ok,
                data,
                errors,
            } => {
                let mut state = serializer.serialize_struct("Frame", 4)?;
                state.serialize_field("id", id)?;
                state.serialize_field("type", "response")?;
                state.serialize_field("ok", ok)?;
                if *ok {
                    state.serialize_field("data", data.as_ref().unwrap_or(&Value::Null))?;
                } else {
                    state.serialize_field("errors", errors)?;
                }
                state.end()
            }
            Self::Error { id, errors } => {
                let mut state = serializer.serialize_struct("Frame", 3)?;
                state.serialize_field("id", id)?;
                state.serialize_field("type", "error")?;
                state.serialize_field("errors", errors)?;
                state.end()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameErrorKind {
    Io,
    Oversize,
    Truncated,
    InvalidUtf8,
    InvalidJson,
    InvalidId,
    UnsupportedType,
}

#[derive(Debug)]
pub(crate) struct FrameError {
    kind: FrameErrorKind,
}

impl FrameError {
    fn new(kind: FrameErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) const fn kind(&self) -> FrameErrorKind {
        self.kind
    }

    #[allow(dead_code)] // The Task 1 client transport is exercised by the local-child integration target.
    pub(crate) fn io() -> Self {
        Self::new(FrameErrorKind::Io)
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            FrameErrorKind::Io => "RPC frame I/O failed",
            FrameErrorKind::Oversize => "RPC frame exceeded its size limit",
            FrameErrorKind::Truncated => "RPC frame ended before its newline",
            FrameErrorKind::InvalidUtf8 => "RPC frame was not valid UTF-8",
            FrameErrorKind::InvalidJson => "RPC frame JSON was malformed",
            FrameErrorKind::InvalidId => "RPC frame identifier was invalid",
            FrameErrorKind::UnsupportedType => "RPC frame type is unsupported",
        })
    }
}

impl std::error::Error for FrameError {}

pub(crate) struct FrameReader<R> {
    input: BufReader<R>,
}

impl<R: Read> FrameReader<R> {
    pub(crate) fn new(input: R) -> Self {
        Self {
            input: BufReader::new(input),
        }
    }

    pub(crate) fn read(&mut self) -> Result<Option<Frame>, FrameError> {
        let mut bytes = Vec::new();
        let read = self
            .input
            .by_ref()
            .take((MAX_FRAME_BYTES + 2) as u64)
            .read_until(b'\n', &mut bytes)
            .map_err(|_| FrameError::new(FrameErrorKind::Io))?;
        if read == 0 {
            return Ok(None);
        }
        if bytes.last() != Some(&b'\n') {
            return Err(FrameError::new(if bytes.len() > MAX_FRAME_BYTES {
                FrameErrorKind::Oversize
            } else {
                FrameErrorKind::Truncated
            }));
        }
        bytes.pop();
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FrameError::new(FrameErrorKind::Oversize));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| FrameError::new(FrameErrorKind::InvalidUtf8))?;
        decode(text).map(Some)
    }
}

pub(crate) struct FrameWriter<W> {
    output: W,
}

impl<W: Write> FrameWriter<W> {
    pub(crate) fn new(output: W) -> Self {
        Self { output }
    }

    pub(crate) fn write(&mut self, frame: &Frame) -> Result<(), FrameError> {
        let bytes =
            serde_json::to_vec(frame).map_err(|_| FrameError::new(FrameErrorKind::InvalidJson))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FrameError::new(FrameErrorKind::Oversize));
        }
        self.output
            .write_all(&bytes)
            .and_then(|()| self.output.write_all(b"\n"))
            .and_then(|()| self.output.flush())
            .map_err(|_| FrameError::new(FrameErrorKind::Io))
    }
}

#[derive(Deserialize)]
struct RawFrame {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    protocol_min: Option<u32>,
    protocol_max: Option<u32>,
    protocol: Option<u32>,
    styrn_version: Option<String>,
    machine_id: Option<String>,
    name: Option<String>,
    manifest_schema_version: Option<u64>,
    method: Option<String>,
    params: Option<Value>,
    ok: Option<bool>,
    data: Option<Value>,
    errors: Option<Vec<RpcDiagnostic>>,
}

#[derive(Clone, Copy)]
struct RawFramePresence {
    protocol_min: bool,
    protocol_max: bool,
    protocol: bool,
    styrn_version: bool,
    machine_id: bool,
    name: bool,
    manifest_schema_version: bool,
    method: bool,
    params: bool,
    ok: bool,
    data: bool,
    errors: bool,
}

impl RawFramePresence {
    fn from_object(object: &Map<String, Value>) -> Self {
        Self {
            protocol_min: object.contains_key("protocol_min"),
            protocol_max: object.contains_key("protocol_max"),
            protocol: object.contains_key("protocol"),
            styrn_version: object.contains_key("styrn_version"),
            machine_id: object.contains_key("machine_id"),
            name: object.contains_key("name"),
            manifest_schema_version: object.contains_key("manifest_schema_version"),
            method: object.contains_key("method"),
            params: object.contains_key("params"),
            ok: object.contains_key("ok"),
            data: object.contains_key("data"),
            errors: object.contains_key("errors"),
        }
    }
}

fn decode(text: &str) -> Result<Frame, FrameError> {
    let unique: UniqueValue =
        serde_json::from_str(text).map_err(|_| FrameError::new(FrameErrorKind::InvalidJson))?;
    let object = unique
        .0
        .as_object()
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
    if !matches!(kind, "hello" | "request" | "response" | "error") {
        return Err(FrameError::new(FrameErrorKind::UnsupportedType));
    }
    let presence = RawFramePresence::from_object(object);
    let raw: RawFrame = serde_json::from_value(unique.0)
        .map_err(|_| FrameError::new(FrameErrorKind::InvalidJson))?;
    if raw.id.len() > MAX_ID_BYTES {
        return Err(FrameError::new(FrameErrorKind::InvalidId));
    }
    match raw.kind.as_str() {
        "hello" => decode_hello(raw, presence),
        "request" => decode_request(raw, presence),
        "response" => decode_response(raw, presence),
        "error" => decode_error(raw, presence),
        _ => unreachable!("frame type was checked"),
    }
}

fn decode_hello(raw: RawFrame, presence: RawFramePresence) -> Result<Frame, FrameError> {
    if raw.id != "hello"
        || presence.method
        || presence.params
        || presence.ok
        || presence.data
        || presence.errors
    {
        return Err(FrameError::new(FrameErrorKind::InvalidJson));
    }
    let version = raw
        .styrn_version
        .filter(|value| !value.is_empty() && value.len() <= MAX_VERSION_BYTES)
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
    match (raw.protocol_min, raw.protocol_max, raw.protocol) {
        (Some(protocol_min), Some(protocol_max), None)
            if protocol_min > 0 && protocol_min <= protocol_max && !presence.protocol =>
        {
            let machine_id = raw
                .machine_id
                .as_deref()
                .and_then(|value| Uuid::parse_str(value).ok())
                .filter(|value| value.to_string() == raw.machine_id.as_deref().unwrap_or_default())
                .filter(|value| {
                    value.get_version_num() == 7 && value.get_variant() == uuid::Variant::RFC4122
                })
                .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
            let name = raw
                .name
                .filter(|value| !value.is_empty() && value.len() <= MAX_NAME_BYTES)
                .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
            let manifest_schema_version = raw
                .manifest_schema_version
                .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
            Ok(Frame::ServerHello(ServerHello {
                protocol_min,
                protocol_max,
                styrn_version: version,
                machine_id,
                name,
                manifest_schema_version,
            }))
        }
        (None, None, Some(protocol))
            if protocol > 0
                && !presence.protocol_min
                && !presence.protocol_max
                && !presence.machine_id
                && !presence.name
                && !presence.manifest_schema_version =>
        {
            Ok(Frame::ClientHello(ClientHello {
                protocol,
                styrn_version: version,
            }))
        }
        _ => Err(FrameError::new(FrameErrorKind::InvalidJson)),
    }
}

fn decode_request(raw: RawFrame, presence: RawFramePresence) -> Result<Frame, FrameError> {
    validate_controller_id(&raw.id)?;
    if presence.protocol_min
        || presence.protocol_max
        || presence.protocol
        || presence.styrn_version
        || presence.machine_id
        || presence.name
        || presence.manifest_schema_version
        || presence.ok
        || presence.data
        || presence.errors
    {
        return Err(FrameError::new(FrameErrorKind::InvalidJson));
    }
    let method = raw
        .method
        .filter(|value| !value.is_empty() && value.len() <= MAX_METHOD_BYTES)
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
    let params = raw
        .params
        .filter(Value::is_object)
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
    Ok(Frame::Request {
        id: raw.id,
        method,
        params,
    })
}

fn decode_response(raw: RawFrame, presence: RawFramePresence) -> Result<Frame, FrameError> {
    validate_controller_id(&raw.id)?;
    if presence.protocol_min
        || presence.protocol_max
        || presence.protocol
        || presence.styrn_version
        || presence.machine_id
        || presence.name
        || presence.manifest_schema_version
        || presence.method
        || presence.params
    {
        return Err(FrameError::new(FrameErrorKind::InvalidJson));
    }
    let ok = raw
        .ok
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
    let errors = raw.errors.unwrap_or_default();
    if ok {
        if raw.data.is_none() || presence.errors {
            return Err(FrameError::new(FrameErrorKind::InvalidJson));
        }
    } else if presence.data || errors.is_empty() || !valid_diagnostics(&errors) {
        return Err(FrameError::new(FrameErrorKind::InvalidJson));
    }
    Ok(Frame::Response {
        id: raw.id,
        ok,
        data: raw.data,
        errors,
    })
}

fn decode_error(raw: RawFrame, presence: RawFramePresence) -> Result<Frame, FrameError> {
    if presence.protocol_min
        || presence.protocol_max
        || presence.protocol
        || presence.styrn_version
        || presence.machine_id
        || presence.name
        || presence.manifest_schema_version
        || presence.method
        || presence.params
        || presence.ok
        || presence.data
    {
        return Err(FrameError::new(FrameErrorKind::InvalidJson));
    }
    if raw.id != "hello" {
        validate_controller_id(&raw.id)?;
    }
    let errors = raw
        .errors
        .filter(|errors| !errors.is_empty() && valid_diagnostics(errors))
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidJson))?;
    Ok(Frame::Error { id: raw.id, errors })
}

fn validate_controller_id(id: &str) -> Result<(), FrameError> {
    let digits = id
        .strip_prefix('c')
        .filter(|digits| !digits.is_empty() && !digits.starts_with('0'))
        .ok_or_else(|| FrameError::new(FrameErrorKind::InvalidId))?;
    if digits.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(FrameError::new(FrameErrorKind::InvalidId))
    }
}

fn valid_diagnostics(errors: &[RpcDiagnostic]) -> bool {
    errors.iter().all(|error| {
        !error.code.is_empty()
            && error.code.len() <= MAX_METHOD_BYTES
            && !error.message.is_empty()
            && error.message.len() <= MAX_DIAGNOSTIC_BYTES
            && error.details.as_ref().is_none_or(Value::is_object)
    })
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object fields")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object field"));
            }
            values.insert(key, object.next_value::<UniqueValue>()?.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}
