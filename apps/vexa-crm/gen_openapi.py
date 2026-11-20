"""Write crm-api's published documents and request models for the native binary (apps/vexa-crm).

    cd core/crm && .venv/bin/python ../../apps/vexa-crm/gen_openapi.py

It writes, under apps/vexa-crm/src:

- openapi.json: the OpenAPI document FastAPI serves at /openapi.json;
- models.json: every request body model and the models nested in it, as JSON schema with the
  field defaults filled (a default factory called) and StrictBool / StrictInt fields marked
  "x-strict": true;
- mcp.tools.v1.json: the manifest /.well-known/mcp-tools.json serves (core/crm/mcp.tools.v1.json);
- pages.json: the HTML FastAPI serves at /docs, /docs/oauth2-redirect and /redoc;
- validate_cases.json: request bodies and the status and JSON FastAPI answers for each, which the
  binary's tests compare its own validation with.
"""
import copy
import json
import os
import pathlib
import sys
import typing

sys.path.insert(0, str(pathlib.Path.cwd() / 'src'))
os.environ['VEXA_FEATURES'] = 'all,public_profiles'

from pydantic import BaseModel  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from crm import api  # noqa: E402
from crm.caller import Caller  # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / 'src'


def write(name, doc, indent=1):
    (OUT / name).write_text(json.dumps(doc, indent=indent, ensure_ascii=False) + '\n')


# ── openapi.json ─────────────────────────────────────────────────────────────────────────────
app = api.create_app(None, None, 'one')
doc = app.openapi()
write('openapi.json', doc)
print(f'openapi.json: {len(doc["paths"])} paths, {len(doc["components"]["schemas"])} schemas')

# ── pages.json ───────────────────────────────────────────────────────────────────────────────
plain = TestClient(app)
pages = {}
for path in ('/docs', '/docs/oauth2-redirect', '/redoc'):
    r = plain.get(path)
    pages[path] = {'status': r.status_code, 'content-type': r.headers['content-type'], 'body': r.text}
write('pages.json', pages)

# ── mcp.tools.v1.json ────────────────────────────────────────────────────────────────────────
(OUT / 'mcp.tools.v1.json').write_text((pathlib.Path.cwd() / 'mcp.tools.v1.json').read_text())


# ── models.json ──────────────────────────────────────────────────────────────────────────────
def strict(annotation):
    if 'Strict(strict=True)' in repr(annotation):
        return True
    return False


def body_models():
    out = {}
    for name in dir(api):
        obj = getattr(api, name)
        if isinstance(obj, type) and issubclass(obj, BaseModel) and obj is not BaseModel and obj.__module__ == api.__name__:
            out[name] = obj
    return out


MODELS = body_models()


def model_schema(model):
    schema = model.model_json_schema(ref_template='{model}')
    schema.pop('$defs', None)
    for name, field in model.model_fields.items():
        prop = schema['properties'][name]
        if not field.is_required():
            prop['default'] = json.loads(json.dumps(field.get_default(call_default_factory=True)))
        if strict(field.annotation):
            prop['x-strict'] = True
    schema['x-forbid'] = model.model_config.get('extra') == 'forbid'
    return schema


models = {name: model_schema(m) for name, m in sorted(MODELS.items())}
write('models.json', models)
print(f'models.json: {len(models)} models')


# ── validate_cases.json ──────────────────────────────────────────────────────────────────────
class _Begin:
    def __enter__(self):
        return None

    def __exit__(self, *a):
        return False


class _Engine:
    def begin(self):
        return _Begin()


class _Profiles:
    def auto_claim(self, c, org, caller):
        return None

    def carry_legacy(self, *a):
        return None


class FakeStore:
    """Answers the person dependency; anything a route itself asks of it fails (a 500)."""
    engine = _Engine()
    profiles = _Profiles()

    def ensure_account(self, org, caller):
        return None


def identity(request):
    return Caller(subject='u1', credential_class='session')


fake = api.create_app(FakeStore(), identity, 'one', 'sekret')
client = TestClient(fake, raise_server_exceptions=False)

ROUTES = {}
for route in fake.routes:
    body = getattr(route, 'body_field', None)
    if body is not None and 'POST' in route.methods:
        ROUTES.setdefault(body.field_info.annotation.__name__, []).append(route.path)


def resolve(schema):
    if '$ref' in schema:
        return models[schema['$ref']]
    return schema


def nonnull(schema):
    for b in schema.get('anyOf', []):
        if b.get('type') != 'null':
            return b
    return schema


def valid(schema):
    schema = resolve(nonnull(schema))
    if 'enum' in schema:
        return schema['enum'][0]
    t = schema.get('type')
    if t == 'string':
        if schema.get('pattern'):
            return '2026-01-31'
        return 'a' * max(schema.get('minLength', 1), 1)
    if t == 'integer':
        return schema.get('minimum', 1)
    if t == 'boolean':
        return True
    if t == 'array':
        return [valid(schema.get('items', {})) for _ in range(schema.get('minItems', 0))]
    if t == 'object' and 'properties' in schema:
        return {k: valid(v) for k, v in schema['properties'].items() if k in schema.get('required', [])}
    if t == 'object':
        return {}
    return 'x'


def wrong(schema):
    """Values a field refuses or coerces, for its type and its constraints."""
    out = []
    nullable = any(b.get('type') == 'null' for b in schema.get('anyOf', []))
    inner = resolve(nonnull(schema))
    if not nullable:
        out.append(None)
    t = inner.get('type')
    if 'enum' in inner:
        out += ['zzz', 1]
    elif t == 'string':
        out += [5, 1.5, True, [], {}]
        if 'maxLength' in inner:
            out.append('é' * (inner['maxLength'] + 1))
        if inner.get('minLength'):
            out.append('')
        if inner.get('pattern'):
            out += ['2026-1-31', '٢٠٢٦-٠١-٣١']
    elif t == 'integer':
        out += ['x', '7', ' 7 ', '1_000', 1.5, 2.0, True, [], '3.0']
        if 'minimum' in inner:
            out.append(inner['minimum'] - 1)
        if 'maximum' in inner:
            out.append(inner['maximum'] + 1)
    elif t == 'boolean':
        out += ['yes', 'maybe', 0, 1, 2, 1.0, 'TRUE', [], 'off']
    elif t == 'array':
        out += ['s', {}, 5, [5]]
        if 'maxItems' in inner:
            out.append([valid(inner.get('items', {}))] * (inner['maxItems'] + 1))
            out.append([5] * (inner['maxItems'] + 1))
        if inner.get('minItems'):
            out.append([])
    elif t == 'object':
        out += [[], 's', 5, True]
        if 'properties' in inner:
            out.append({'zz': 1})
            out.append({k: 5 for k in inner['properties']})
    return out


cases = []


def case(path, body, content_type='application/json', raw=None):
    headers = {'x-internal-secret': 'sekret', 'authorization': 'Bearer t'}
    if content_type is not None:
        headers['content-type'] = content_type
    data = raw if raw is not None else json.dumps(body).encode()
    r = client.post(path, content=data, headers=headers)
    try:
        answer = r.json()
    except ValueError:
        answer = r.text
    cases.append({'path': path, 'body': data.decode('utf-8', 'replace'), 'body_hex': data.hex(),
                  'content_type': content_type, 'status': r.status_code, 'answer': answer})


for name, paths in sorted(ROUTES.items()):
    schema = models[name]
    path = paths[0]
    base = valid(schema)
    props = schema['properties']
    for field in props:
        if field in schema.get('required', []):
            b = copy.deepcopy(base)
            b.pop(field, None)
            case(path, b)
        for w in wrong(props[field]):
            b = copy.deepcopy(base)
            b[field] = w
            case(path, b)
    b = copy.deepcopy(base)
    b['zz_extra'] = 1
    b['aa_extra'] = [1]
    case(path, b)
    everything = {'zz_extra': 1}
    everything.update({f: [[]] for f in props})
    case(path, everything)
    case(path, {})
    case(path, [])
    case(path, None)
    case(path, 'text')
    case(path, None, raw=b'')
    case(path, None, raw=b'{"a": ')
    case(path, None, raw=b'{"a": 1} x')
    case(path, None, raw=b'\xff\xfe{')
    case(path, None, content_type='text/plain', raw=b'{}')
    case(path, None, content_type=None, raw=b'{}')
    case(path, None, content_type='application/vnd.x+json', raw=b'[1]')

def trim(cases, budget=190_000):
    """The smallest case of each (path, status, first error type), in order, within the byte budget."""
    def kind(c):
        d = c['answer'].get('detail') if isinstance(c['answer'], dict) else None
        first = d[0]['type'] if isinstance(d, list) and d else str(d)[:40]
        return (c['path'], c['status'], first)
    best = {}
    for i, c in enumerate(cases):
        size = len(json.dumps(c))
        k = kind(c)
        if k not in best or size < best[k][1]:
            best[k] = (i, size)
    keep, total = [], 0
    for i, size in sorted(best.values(), key=lambda t: t[1]):
        if total + size > budget:
            continue
        keep.append(i)
        total += size
    return [cases[i] for i in sorted(keep)]


if os.environ.get('VALIDATE_CASES_FULL'):
    write_path = os.environ['VALIDATE_CASES_FULL']
    with open(write_path, 'w') as fh:
        json.dump(cases, fh, ensure_ascii=False)
cases = trim(cases)
write('validate_cases.json', cases, indent=None)
print(f'validate_cases.json: {len(cases)} cases over {len(ROUTES)} models')
