import pytest

from spectree.utils import get_model_key, get_model_path_key, get_model_schema

from .common import JSON, SECURITY_SCHEMAS, Cookies, Headers, Query, Resp, get_paths
from .test_plugin_falcon import api as falcon_api
from .test_plugin_flask import api as flask_api
from .test_plugin_flask import api_global_secure as flask_api_global_secure
from .test_plugin_flask import api_secure as flask_api_secure
from .test_plugin_flask_blueprint import api as flask_bp_api
from .test_plugin_flask_view import api as flask_view_api
from .test_plugin_starlette import api as starlette_api


@pytest.mark.parametrize(
    "api",
    [
        flask_api,
        flask_bp_api,
        flask_view_api,
        falcon_api,
        starlette_api,
    ],
)
def test_plugin_spec(api):
    models = {
        get_model_key(model=m): get_model_schema(model=m)
        for m in (Query, JSON, Resp, Cookies, Headers)
    }
    for name, schema in models.items():
        schema.pop("definitions", None)
        assert api.spec["components"]["schemas"][name] == schema

    assert api.spec["tags"] == [
        {"name": "test"},
        {"name": "health"},
        {
            "description": "🐱",
            "externalDocs": {
                "description": "",
                "url": "https://pypi.org",
            },
            "name": "API",
        },
    ]

    assert get_paths(api.spec) == [
        "/api/user/{name}",
        "/api/user_annotated/{name}",
        "/ping",
    ]

    ping = api.spec["paths"]["/ping"]["get"]
    assert ping["tags"] == ["test", "health"]
    assert ping["parameters"][0]["in"] == "header"
    assert ping["summary"] == "summary"
    assert ping["description"] == "description"
    assert ping["operationId"] == "get_/ping"

    user = api.spec["paths"]["/api/user/{name}"]["post"]
    assert user["tags"] == ["API", "test"]
    assert (
        user["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        == f"#/components/schemas/{get_model_path_key('tests.common.JSON')}"
    )
    assert len(user["responses"]) == 3

    params = user["parameters"]
    for param in params:
        if param["in"] == "path":
            assert param["name"] == "name"
        elif param["in"] == "query":
            assert param["name"] == "order"


def test_secure_spec():
    assert [*flask_api_secure.spec["components"]["securitySchemes"].keys()] == [
        scheme.name for scheme in SECURITY_SCHEMAS
    ]

    paths = flask_api_secure.spec["paths"]
    # iter paths
    for path, path_data in paths.items():
        security = path_data["get"].get("security")
        # check empty-secure path
        if path == "/no-secure-ping":
            assert security is None
        else:
            # iter secure names and params
            for secure_key, secure_value in security[0].items():
                # check secure names valid
                assert secure_key in [scheme.name for scheme in SECURITY_SCHEMAS]

                # check if flow exist
                if secure_value:
                    scopes = [
                        scheme.data.flows["authorizationCode"]["scopes"]
                        for scheme in SECURITY_SCHEMAS
                        if scheme.name == secure_key
                    ]

                    assert set(secure_value).issubset(*scopes)


def test_secure_global_spec():
    assert [*flask_api_global_secure.spec["components"]["securitySchemes"].keys()] == [
        scheme.name for scheme in SECURITY_SCHEMAS
    ]

    paths = flask_api_global_secure.spec["paths"]
    global_security = flask_api_global_secure.spec["security"]

    assert global_security == [{"auth_apiKey": []}]

    # iter paths
    for path, path_data in paths.items():
        security = path_data["get"].get("security")
        # check empty-secure path
        if path == "/no-secure-override-ping":
            # check if it is defined overridden no auth specification
            assert security == []
        elif path == "/oauth2-flows-override-ping":
            # check if it is defined overridden security specification
            assert security == [{"auth_oauth2": ["admin", "read"]}]
        elif path == "/global-secure-ping":
            # check if local security specification is missing,
            # when was not specified explicitly
            assert security is None
        elif path == "/security_and":
            # check if AND operation is supported
            assert security == [{"auth_apiKey": [], "auth_apiKey_backup": []}]
        elif path == "/security_or":
            # check if OR operation is supported
            assert security == [{"auth_apiKey": []}, {"auth_apiKey_backup": []}]
