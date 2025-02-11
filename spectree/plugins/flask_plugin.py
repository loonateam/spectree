from pydantic import ValidationError

from .base import BasePlugin, Context
from .page import PAGES
from ..utils import werkzeug_parse_rule


class FlaskPlugin(BasePlugin):
    blueprint_state = None
    FORM_MIMETYPE = ("application/x-www-form-urlencoded", "multipart/form-data")

    def find_routes(self):
        from flask import current_app

        for rule in current_app.url_map.iter_rules():
            if any(
                str(rule).startswith(path)
                for path in (f"/{self.config.PATH}", "/static")
            ):
                continue
            if rule.endpoint.startswith("openapi"):
                continue
            if (
                self.blueprint_state
                and self.blueprint_state.url_prefix
                and str(rule).startswith(self.blueprint_state.url_prefix)
            ):
                continue
            yield rule

    def get_api_versions(self):
        """
        Get all versions API according to config VERSION_REGEX
        """
        with self.spectree.app.app_context():
            versions = {
                result.group(1)
                for version in self.find_routes()
                if self.config.VERSION_REGEX
                and (result := self.spectree.version_regex.match(str(version)))
            }
            versions.add("")
            return versions

    def bypass(self, func, method):
        return method in ["HEAD", "OPTIONS"]

    def parse_func(self, route):
        from flask import current_app

        if self.blueprint_state:
            func = self.blueprint_state.app.view_functions[route.endpoint]
        else:
            func = current_app.view_functions[route.endpoint]

        # view class: https://flask.palletsprojects.com/en/1.1.x/views/
        if getattr(func, "view_class", None):
            cls = getattr(func, "view_class")
            for method in route.methods:
                view = getattr(cls, method.lower(), None)
                if view:
                    yield method, view
        else:
            for method in route.methods:
                yield method, func

    def parse_path(self, route):
        from werkzeug.routing import parse_converter_args

        subs = []
        parameters = []

        for converter, arguments, variable in werkzeug_parse_rule(str(route)):
            if converter is None:
                subs.append(variable)
                continue
            subs.append(f"{{{variable}}}")

            args, kwargs = [], {}

            if arguments:
                args, kwargs = parse_converter_args(arguments)

            schema = None
            if converter == "any":
                schema = {
                    "type": "string",
                    "enum": args,
                }
            elif converter == "int":
                schema = {
                    "type": "integer",
                    "format": "int32",
                }
                if "max" in kwargs:
                    schema["maximum"] = kwargs["max"]
                if "min" in kwargs:
                    schema["minimum"] = kwargs["min"]
            elif converter == "float":
                schema = {
                    "type": "number",
                    "format": "float",
                }
            elif converter == "uuid":
                schema = {
                    "type": "string",
                    "format": "uuid",
                }
            elif converter == "path":
                schema = {
                    "type": "string",
                    "format": "path",
                }
            elif converter == "string":
                schema = {
                    "type": "string",
                }
                for prop in ["length", "maxLength", "minLength"]:
                    if prop in kwargs:
                        schema[prop] = kwargs[prop]
            elif converter == "default":
                schema = {"type": "string"}

            parameters.append(
                {
                    "name": variable,
                    "in": "path",
                    "required": True,
                    "schema": schema,
                }
            )

        return "".join(subs), parameters

    def request_validation(self, request, query, json, headers, cookies):
        req_query = request.args or {}
        if request.mimetype in self.FORM_MIMETYPE:
            req_json = request.form or {}
            if request.files:
                req_json = dict(
                    list(request.form.items()) + list(request.files.items())
                )
        else:
            req_json = request.get_json(silent=True) or {}
        req_headers = request.headers or {}
        req_cookies = request.cookies or {}
        request.context = Context(
            query.parse_obj(req_query.items()) if query else None,
            json.parse_obj(req_json.items()) if json else None,
            headers.parse_obj(req_headers.items()) if headers else None,
            cookies.parse_obj(req_cookies.items()) if cookies else None,
        )

    def validate(
        self, func, query, json, headers, cookies, resp, before, after, *args, **kwargs
    ):
        from flask import abort, jsonify, make_response, request

        response, req_validation_error, resp_validation_error = None, None, None
        try:
            self.request_validation(request, query, json, headers, cookies)
            if self.config.ANNOTATIONS:
                for name in ("query", "json", "headers", "cookies"):
                    if func.__annotations__.get(name):
                        kwargs[name] = getattr(request.context, name)
        except ValidationError as err:
            req_validation_error = err
            response = make_response(jsonify(err.errors()), 422)

        before(request, response, req_validation_error, None)
        if req_validation_error:
            after(request, response, req_validation_error, None)
            abort(response)

        response = make_response(func(*args, **kwargs))

        if resp and resp.has_model():
            model = resp.find_model(response.status_code)
            if model:
                try:
                    model.parse_obj(response.get_json())
                except ValidationError as err:
                    resp_validation_error = err
                    response = make_response(
                        jsonify({"message": "response validation error"}), 500
                    )

        after(request, response, resp_validation_error, None)

        return response

    def register_route(self, app):
        from flask import Blueprint, jsonify

        for version in self.get_api_versions():
            app.add_url_rule(
                rule=self.config.get_version_url(version),
                endpoint=f"openapi_{self.config.PATH}_{version}",
                view_func=lambda vers=version: jsonify(
                    self.spectree._generate_spec(vers)
                ),
            )

            if isinstance(app, Blueprint):

                def gen_doc_page(ui):
                    spec_url = self.config.spec_url
                    if self.blueprint_state.url_prefix is not None:
                        spec_url = "/".join(
                            (
                                self.blueprint_state.url_prefix.rstrip("/"),
                                self.config.spec_url.lstrip("/"),
                            )
                        )

                    return PAGES[ui].format(spec_url)

                for ui in PAGES:
                    app.add_url_rule(
                        rule=f"/{self.config.PATH}/{ui}",
                        endpoint=f"openapi_{self.config.PATH}_{ui}",
                        view_func=lambda ui=ui: gen_doc_page(ui),
                    )

                app.record(lambda state: setattr(self, "blueprint_state", state))
            else:
                for ui in PAGES:
                    app.add_url_rule(
                        rule=f"/{self.config.PATH}{f'/{version}' if version else ''}/{ui}",
                        endpoint=f"openapi_{self.config.PATH}{version.strip('/')}_{ui}",
                        view_func=lambda ui=ui, vers=version: PAGES[ui].format(
                            self.config.get_version_url(vers)
                        ),
                    )
