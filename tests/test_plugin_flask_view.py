import json
from random import randint

import pytest
from flask import Flask, jsonify, request
from flask.views import MethodView

from spectree import Response, SpecTree

from .common import JSON, Cookies, Headers, Query, Resp, StrDict, api_tag


def before_handler(req, resp, err, _):
    if err:
        resp.headers["X-Error"] = "Validation Error"


def after_handler(req, resp, err, _):
    resp.headers["X-Validation"] = "Pass"


def api_after_handler(req, resp, err, _):
    resp.headers["X-API"] = "OK"


api_version = "v1"
api_prefix = "api"
api = SpecTree(
    "flask",
    before=before_handler,
    after=after_handler,
    api_prefix=api_prefix,
    api_versions=["/", f"/{api_version}"],
    annotations=True,
)

app = Flask(__name__)
app.config["TESTING"] = True


class Ping(MethodView):
    @api.validate(
        headers=Headers, resp=Response(HTTP_200=StrDict), tags=["test", "health"]
    )
    def get(self):
        """summary

        description"""
        return jsonify(msg="pong")


class User(MethodView):
    @api.validate(
        query=Query,
        json=JSON,
        cookies=Cookies,
        resp=Response(HTTP_200=Resp, HTTP_401=None),
        tags=[api_tag, "test"],
        after=api_after_handler,
    )
    def post(self, name):
        score = [randint(0, request.context.json.limit) for _ in range(5)]
        score.sort(reverse=request.context.query.order)
        assert request.context.cookies.pub == "abcdefg"
        assert request.cookies["pub"] == "abcdefg"
        return jsonify(name=request.context.json.name, score=score)


class UserAnnotated(MethodView):
    @api.validate(
        resp=Response(HTTP_200=Resp, HTTP_401=None),
        tags=[api_tag, "test"],
        after=api_after_handler,
    )
    def post(self, name, query: Query, json: JSON, cookies: Cookies):
        score = [randint(0, json.limit) for _ in range(5)]
        score.sort(reverse=query.order)
        assert cookies.pub == "abcdefg"
        assert request.cookies["pub"] == "abcdefg"
        return jsonify(name=json.name, score=score)


for version in ["", f"/{api_version}"]:
    app.add_url_rule(
        f"/{api_prefix}{version}/ping",
        endpoint=f'ping{f"_{version}" if version else ""}',
        view_func=Ping.as_view("ping"),
    )
    app.add_url_rule(
        f"/{api_prefix}{version}/user/<name>",
        endpoint=f'user{f"_{version}" if version else ""}',
        view_func=User.as_view("user"),
        methods=["POST"],
    )
    app.add_url_rule(
        f"/api{version}/user_annotated/<name>",
        endpoint=f'user_annotated{f"_{version}" if version else ""}',
        view_func=UserAnnotated.as_view("user_annotated"),
        methods=["POST"],
    )

# INFO: ensures that spec is calculated and cached _after_ registering
# view functions for validations. This enables tests to access `api.spec`
# without app_context.
with app.app_context():
    api.spec


api.register(app)


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


def test_flask_validate(client):
    resp = client.get(f"{api_prefix}{version}/ping")
    assert resp.status_code == 422
    assert resp.headers.get("X-Error") == "Validation Error"

    resp = client.get(f"{api_prefix}{version}/ping", headers={"lang": "en-US"})
    assert resp.json == {"msg": "pong"}
    assert resp.headers.get("X-Error") is None
    assert resp.headers.get("X-Validation") == "Pass"

    resp = client.post(f"{api_prefix}{version}/user/flask")
    assert resp.status_code == 422
    assert resp.headers.get("X-Error") == "Validation Error"

    client.set_cookie("flask", "pub", "abcdefg")
    for fragment in ("user", "user_annotated"):
        resp = client.post(
            f"{api_prefix}{version}/{fragment}/flask?order=1",
            data=json.dumps(dict(name="flask", limit=10)),
            content_type="application/json",
        )
        assert resp.status_code == 200, resp.json
        assert resp.headers.get("X-Validation") is None
        assert resp.headers.get("X-API") == "OK"
        assert resp.json["name"] == "flask"
        assert resp.json["score"] == sorted(resp.json["score"], reverse=True)

        resp = client.post(
            f"{api_prefix}{version}/{fragment}/flask?order=0",
            data=json.dumps(dict(name="flask", limit=10)),
            content_type="application/json",
        )
        assert resp.json["score"] == sorted(resp.json["score"], reverse=False)

        resp = client.post(
            f"{api_prefix}{version}/{fragment}/flask?order=0",
            data="name=flask&limit=10",
            content_type="application/x-www-form-urlencoded",
        )
        assert resp.json["score"] == sorted(resp.json["score"], reverse=False)


@pytest.mark.parametrize("version", ["", f"/{api_version}"], ids=["v0", api_version])
def test_flask_doc(client, version):
    resp = client.get(f"/apidoc{version}/openapi.json")
    assert all(True for key in resp.json.get("paths").keys() if version in key)

    resp = client.get(f"/apidoc{version}/redoc")
    assert resp.status_code == 200

    resp = client.get(f"/apidoc{version}/swagger")
    assert resp.status_code == 200
