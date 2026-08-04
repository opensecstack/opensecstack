import json

from flask import Blueprint, Response, jsonify

openapi_bp = Blueprint("openapi", __name__)

# Full OpenAPI 3.0.3 specification for NIS2 Compass API
_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "NIS2 Compass API",
        "version": "1.0.0",
        "description": (
            "REST API for the NIS2 Compass compliance management platform. "
            "Helps organisations assess and track adherence to EU NIS2 Directive "
            "Article 21(2) cybersecurity risk-management measures."
        ),
        "contact": {"name": "OpenSecStack", "url": "https://github.com/opensecstack/opensecstack"},
    },
    "servers": [{"url": "/api/v1", "description": "API v1"}],
    "security": [{"bearerAuth": []}],
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}},
        "schemas": {
            "Error": {
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "code": {
                        "type": "string",
                        "enum": [
                            "INVALID_INPUT",
                            "NOT_FOUND",
                            "UNAUTHORIZED",
                            "FORBIDDEN",
                            "CONFLICT",
                            "RATE_LIMITED",
                            "INTERNAL_ERROR",
                        ],
                    },
                },
            },
            "Organisation": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "name": {"type": "string"},
                    "industry": {"type": "string"},
                    "country": {"type": "string", "minLength": 2, "maxLength": 2},
                    "size": {"type": "string", "enum": ["micro", "small", "medium", "large"]},
                    "entity_type": {"type": "string", "enum": ["essential", "important"]},
                    "registration_number": {"type": "string", "nullable": True},
                    "contact_email": {"type": "string", "nullable": True},
                    "created_at": {"type": "string", "format": "date-time"},
                    "updated_at": {"type": "string", "format": "date-time"},
                },
            },
            "Assessment": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "org_id": {"type": "string", "format": "uuid"},
                    "title": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["draft", "in_progress", "under_review", "completed", "archived"],
                    },
                    "framework_version": {"type": "string"},
                    "scope": {"type": "string", "nullable": True},
                    "assessor": {"type": "string", "nullable": True},
                    "due_date": {"type": "string", "format": "date", "nullable": True},
                    "completed_at": {"type": "string", "format": "date-time", "nullable": True},
                    "created_at": {"type": "string", "format": "date-time"},
                    "updated_at": {"type": "string", "format": "date-time"},
                },
            },
            "Control": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "assessment_id": {"type": "string", "format": "uuid"},
                    "article_ref": {"type": "string"},
                    "measure_ref": {"type": "string", "enum": list("abcdefghij")},
                    "nist_category": {
                        "type": "string",
                        "enum": ["identify", "protect", "detect", "respond", "recover"],
                    },
                    "title": {"type": "string"},
                    "status": {
                        "type": "string",
                        "enum": ["not_assessed", "compliant", "partially_compliant", "non_compliant", "not_applicable"],
                    },
                    "evidence": {"type": "object"},
                    "gap_description": {"type": "string", "nullable": True},
                    "remediation_plan": {"type": "string", "nullable": True},
                    "remediation_due": {"type": "string", "format": "date", "nullable": True},
                    "risk_score": {"type": "number", "minimum": 0, "maximum": 10, "nullable": True},
                    "notes": {"type": "string", "nullable": True},
                    "remediation_owner": {
                        "type": "string",
                        "nullable": True,
                        "maxLength": 255,
                        "description": "Person or team responsible for remediation",
                    },
                    "remediation_status": {
                        "type": "string",
                        "nullable": True,
                        "enum": ["not_started", "in_progress", "blocked", "completed"],
                        "description": "Progress of the remediation effort",
                    },
                    "external_ticket_url": {
                        "type": "string",
                        "nullable": True,
                        "maxLength": 2048,
                        "description": "URL of the linked Jira/GitHub/Linear ticket (must start with http:// or https://)",
                    },
                    "remediation_notes": {
                        "type": "string",
                        "nullable": True,
                        "description": "Free-text notes on the remediation effort",
                    },
                    "assessed_by": {"type": "string", "nullable": True},
                    "assessed_at": {"type": "string", "format": "date-time", "nullable": True},
                },
            },
            "Artifact": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "assessment_id": {"type": "string", "format": "uuid"},
                    "control_id": {"type": "string", "format": "uuid", "nullable": True},
                    "type": {
                        "type": "string",
                        "enum": [
                            "policy",
                            "procedure",
                            "evidence",
                            "report",
                            "screenshot",
                            "log",
                            "certificate",
                            "contract",
                        ],
                    },
                    "filename": {"type": "string"},
                    "hash": {"type": "string", "description": "SHA-256 hex digest of file content"},
                    "size_bytes": {"type": "integer", "nullable": True},
                    "mime_type": {"type": "string", "nullable": True},
                    "description": {"type": "string", "nullable": True},
                    "created_by": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"},
                },
            },
            "AuditEntry": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "action": {"type": "string"},
                    "actor": {"type": "string"},
                    "resource_type": {"type": "string"},
                    "resource_id": {"type": "string", "format": "uuid", "nullable": True},
                    "risk_class": {"type": "string", "enum": ["INFO", "WARNING", "CRITICAL"]},
                    "metadata": {"type": "object"},
                    "object_fingerprint": {"type": "string", "nullable": True},
                    "prev_hash": {"type": "string", "nullable": True},
                    "chain_hash": {"type": "string"},
                    "timestamp": {"type": "string", "format": "date-time"},
                },
            },
            "ControlTemplate": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "measure_ref": {"type": "string"},
                    "article_ref": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "nist_category": {"type": "string"},
                    "guidance": {"type": "string", "nullable": True},
                },
            },
        },
    },
    "paths": {
        "/health": {
            "get": {
                "tags": ["System"],
                "summary": "Liveness check",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Service is running",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"status": {"type": "string"}, "version": {"type": "string"}},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/auth/token": {
            "post": {
                "tags": ["Authentication"],
                "summary": "Exchange API key for JWT",
                "security": [],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["api_key"],
                                "properties": {"api_key": {"type": "string"}},
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Token issued",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "access_token": {"type": "string"},
                                        "refresh_token": {"type": "string"},
                                        "token_type": {"type": "string"},
                                        "expires_in": {"type": "integer"},
                                    },
                                }
                            }
                        },
                    },
                    "401": {
                        "description": "Invalid API key",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                    },
                    "429": {"description": "Rate limit exceeded"},
                },
            }
        },
        "/organisations": {
            "get": {
                "tags": ["Organisations"],
                "summary": "List organisations",
                "parameters": [
                    {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                    {"name": "per_page", "in": "query", "schema": {"type": "integer", "default": 20}},
                ],
                "responses": {
                    "200": {
                        "description": "List of organisations",
                        "headers": {"X-Total-Count": {"schema": {"type": "integer"}}},
                        "content": {
                            "application/json": {
                                "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Organisation"}}
                            }
                        },
                    }
                },
            },
            "post": {
                "tags": ["Organisations"],
                "summary": "Create organisation",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name", "industry", "country"],
                                "properties": {
                                    "name": {"type": "string"},
                                    "industry": {"type": "string"},
                                    "country": {"type": "string"},
                                    "size": {"type": "string", "enum": ["micro", "small", "medium", "large"]},
                                    "entity_type": {"type": "string", "enum": ["essential", "important"]},
                                    "registration_number": {"type": "string"},
                                    "contact_email": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Organisation created",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Organisation"}}},
                    },
                    "400": {"description": "Invalid input"},
                    "409": {"description": "Name conflict"},
                },
            },
        },
        "/organisations/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Organisations"],
                "summary": "Get organisation",
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Organisation"}}}},
                    "404": {"description": "Not found"},
                },
            },
            "patch": {
                "tags": ["Organisations"],
                "summary": "Update organisation",
                "requestBody": {
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Organisation"}}}
                },
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Organisation"}}}}
                },
            },
            "delete": {
                "tags": ["Organisations"],
                "summary": "Delete organisation",
                "responses": {"204": {"description": "Deleted"}, "404": {"description": "Not found"}},
            },
        },
        "/organisations/{org_id}/assessments": {
            "parameters": [
                {"name": "org_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Assessments"],
                "summary": "List assessments for organisation",
                "parameters": [
                    {"name": "status", "in": "query", "schema": {"type": "string"}},
                    {"name": "page", "in": "query", "schema": {"type": "integer"}},
                    {"name": "per_page", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Assessment"}}
                            }
                        }
                    }
                },
            },
            "post": {
                "tags": ["Assessments"],
                "summary": "Create assessment (auto-creates 10 controls)",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["title"],
                                "properties": {
                                    "title": {"type": "string"},
                                    "framework_version": {"type": "string"},
                                    "scope": {"type": "string"},
                                    "assessor": {"type": "string"},
                                    "due_date": {"type": "string", "format": "date"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "201": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Assessment"}}}}
                },
            },
        },
        "/assessments/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Assessments"],
                "summary": "Get assessment with stats",
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Assessment"}}}}
                },
            },
            "patch": {
                "tags": ["Assessments"],
                "summary": "Update assessment status/fields",
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Assessment"}}}}
                },
            },
            "delete": {
                "tags": ["Assessments"],
                "summary": "Delete assessment",
                "responses": {"204": {"description": "Deleted"}},
            },
        },
        "/assessments/{id}/controls": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Controls"],
                "summary": "List controls for assessment",
                "parameters": [
                    {"name": "status", "in": "query", "schema": {"type": "string"}},
                    {"name": "nist_category", "in": "query", "schema": {"type": "string"}},
                    {"name": "measure_ref", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Control"}}
                            }
                        }
                    }
                },
            },
        },
        "/assessments/{id}/controls/{measure_ref}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
                {
                    "name": "measure_ref",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "enum": list("abcdefghij")},
                },
            ],
            "get": {
                "tags": ["Controls"],
                "summary": "Get control by measure ref",
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Control"}}}}
                },
            },
            "patch": {
                "tags": ["Controls"],
                "summary": "Update control status and evidence",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "status": {
                                        "type": "string",
                                        "enum": [
                                            "not_assessed",
                                            "compliant",
                                            "partially_compliant",
                                            "non_compliant",
                                            "not_applicable",
                                        ],
                                    },
                                    "evidence": {"type": "object"},
                                    "gap_description": {"type": "string"},
                                    "remediation_plan": {"type": "string"},
                                    "remediation_due": {"type": "string", "format": "date"},
                                    "risk_score": {"type": "number", "minimum": 0, "maximum": 10},
                                    "notes": {"type": "string"},
                                    "remediation_owner": {
                                        "type": "string",
                                        "maxLength": 255,
                                        "description": "Person or team responsible for remediation",
                                    },
                                    "remediation_status": {
                                        "type": "string",
                                        "enum": ["not_started", "in_progress", "blocked", "completed"],
                                        "description": "Progress of the remediation effort",
                                    },
                                    "external_ticket_url": {
                                        "type": "string",
                                        "maxLength": 2048,
                                        "description": "URL of the linked Jira/GitHub/Linear ticket (must start with http:// or https://)",
                                    },
                                    "remediation_notes": {
                                        "type": "string",
                                        "description": "Free-text notes on the remediation effort",
                                    },
                                },
                            }
                        }
                    }
                },
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Control"}}}}
                },
            },
        },
        "/assessments/{id}/artifacts": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Artifacts"],
                "summary": "List artifacts for assessment",
                "parameters": [
                    {"name": "control_id", "in": "query", "schema": {"type": "string", "format": "uuid"}},
                    {"name": "type", "in": "query", "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Artifact"}}
                            }
                        }
                    }
                },
            },
            "post": {
                "tags": ["Artifacts"],
                "summary": "Upload artifact",
                "requestBody": {
                    "required": True,
                    "content": {
                        "multipart/form-data": {
                            "schema": {
                                "type": "object",
                                "required": ["file", "type"],
                                "properties": {
                                    "file": {"type": "string", "format": "binary"},
                                    "type": {"type": "string"},
                                    "control_id": {"type": "string", "format": "uuid"},
                                    "description": {"type": "string"},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "201": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Artifact"}}}},
                    "413": {"description": "File too large"},
                },
            },
        },
        "/artifacts/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Artifacts"],
                "summary": "Get artifact metadata",
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Artifact"}}}}
                },
            },
            "delete": {
                "tags": ["Artifacts"],
                "summary": "Delete artifact record",
                "responses": {"204": {"description": "Deleted"}},
            },
        },
        "/artifacts/{id}/download": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Artifacts"],
                "summary": "Download artifact file",
                "description": "Streams the artifact file as an attachment. Returns 410 Gone if the file has been removed from disk.",
                "responses": {
                    "200": {
                        "description": "File content streamed as attachment",
                        "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}},
                    },
                    "404": {
                        "description": "Artifact record not found",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                    },
                    "410": {
                        "description": "File no longer available on disk",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                    },
                },
            },
        },
        "/audit": {
            "get": {
                "tags": ["Audit Log"],
                "summary": "List audit log entries",
                "parameters": [
                    {"name": "actor", "in": "query", "schema": {"type": "string"}},
                    {"name": "action", "in": "query", "schema": {"type": "string"}},
                    {"name": "resource_type", "in": "query", "schema": {"type": "string"}},
                    {"name": "resource_id", "in": "query", "schema": {"type": "string", "format": "uuid"}},
                    {
                        "name": "risk_class",
                        "in": "query",
                        "schema": {"type": "string", "enum": ["INFO", "WARNING", "CRITICAL"]},
                    },
                    {
                        "name": "after",
                        "in": "query",
                        "schema": {"type": "string", "format": "date-time"},
                        "description": "Return entries after this ISO 8601 timestamp (cursor-based polling)",
                    },
                    {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                    {"name": "per_page", "in": "query", "schema": {"type": "integer", "default": 20}},
                ],
                "responses": {
                    "200": {
                        "description": "Audit entries",
                        "headers": {"X-Total-Count": {"schema": {"type": "integer"}}},
                        "content": {
                            "application/json": {
                                "schema": {"type": "array", "items": {"$ref": "#/components/schemas/AuditEntry"}}
                            }
                        },
                    }
                },
            }
        },
        "/audit/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}
            ],
            "get": {
                "tags": ["Audit Log"],
                "summary": "Get single audit entry",
                "responses": {
                    "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/AuditEntry"}}}},
                    "404": {"description": "Not found"},
                },
            },
        },
        "/control-templates": {
            "get": {
                "tags": ["Control Templates"],
                "summary": "List NIS2 Article 21(2) control templates",
                "parameters": [
                    {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                    {"name": "per_page", "in": "query", "schema": {"type": "integer", "default": 20, "maximum": 100}},
                ],
                "responses": {
                    "200": {
                        "headers": {
                            "X-Total-Count": {
                                "schema": {"type": "integer"},
                                "description": "Total number of control templates",
                            }
                        },
                        "content": {
                            "application/json": {
                                "schema": {"type": "array", "items": {"$ref": "#/components/schemas/ControlTemplate"}}
                            }
                        },
                    }
                },
            }
        },
    },
}


@openapi_bp.get("/openapi.json")
def openapi_json():
    """Serve the OpenAPI 3.0.3 specification as JSON."""
    return Response(
        json.dumps(_SPEC, indent=2),
        mimetype="application/json",
    )


@openapi_bp.get("/docs")
def swagger_ui():
    """Serve Swagger UI for interactive API exploration."""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NIS2 Compass API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({{
      url: '/api/v1/openapi.json',
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
    }});
  </script>
</body>
</html>"""
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}
