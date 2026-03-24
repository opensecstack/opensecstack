use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// APIGuard Internal Representation.
/// This is the normalised form all downstream layers consume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiGuardIR {
    pub endpoints: Vec<Endpoint>,
    pub auth_schemes: Vec<AuthScheme>,
    pub metadata: Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub path: String,
    pub method: HttpMethod,
    pub parameters: Vec<Parameter>,
    pub request_body: Option<RequestBody>,
    pub responses: HashMap<String, Response>,
    pub security: Vec<String>,
    pub tags: Vec<String>,
    pub x_apiguard: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
    pub schema: Option<SchemaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub content_types: Vec<String>,
    pub schema: Option<SchemaType>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub description: String,
    pub schema: Option<SchemaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthScheme {
    pub name: String,
    pub scheme_type: AuthSchemeType,
    /// For apikey: header, query, or cookie.
    pub location: Option<String>,
    /// For apikey/bearer: the header name.
    pub header_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub base_url: String,
    pub api_version: String,
    /// SHA-256 hex digest of the raw input bytes.
    pub schema_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthSchemeType {
    Bearer,
    Jwt,
    OAuth2,
    ApiKey,
    Basic,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    String,
    Integer,
    Number,
    Boolean,
    Array(Box<SchemaType>),
    Object(HashMap<String, SchemaType>),
    Ref(String),
}

/// Input format hint for the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    OpenApi3,
    Swagger2,
    GraphQL,
    Postman,
}
