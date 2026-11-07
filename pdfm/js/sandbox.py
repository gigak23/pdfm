"""Emulate a document's JavaScript in an isolated V8 with fake Acrobat APIs.

mini-racer embeds bare V8: no filesystem, network, require, or process, so the
only things a script can touch are the stubs defined here. Every Acrobat object
is a recording Proxy: any property chain or call (Collab.getIcon(...),
this.exportDataObject(...)) is logged instead of failing, so execution gets as
far as possible. app.viewerVersion reports a vulnerable version (9.0) so exploit
code that checks the version takes its malicious branch.

No Python callbacks are exposed to the script, which keeps the bridge surface at
zero. Still, a V8 bug could escape any sandbox, so analyze live samples in a VM.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

try:
    from py_mini_racer import JSEvalException, JSTimeoutException, MiniRacer
except ImportError:  # optional dependency: pip install pdfm[sandbox]
    MiniRacer = None

SCRIPT_TIMEOUT = 3.0  # seconds per script
MEMORY_LIMIT = 256 * 1024 * 1024
MAX_EVAL_CAPTURE = 1024 * 1024
MAX_PAYLOAD_CAPTURE = 64 * 1024

PRELUDE = r"""
var __calls = [], __evals = [], __payloads = [];
function __str(a) {
  try {
    var s;
    if (typeof a === 'string') s = a;
    else if (a === globalThis) s = 'this';  // its fallback prototype answers every property, even __pdfmPath
    else if (typeof a === 'function' && typeof a.__pdfmPath === 'string') s = a.__pdfmPath;
    else s = JSON.stringify(a);
    if (typeof s !== 'string') s = Object.prototype.toString.call(a);
    return s.length > 300 ? s.slice(0, 300) + '...[' + s.length + ' chars]' : s;
  } catch (e) { return '?'; }
}
function __stub(path, overrides) {
  overrides = overrides || {};
  return new Proxy(function () {}, {
    get: function (t, p) {
      if (p === Symbol.toPrimitive) return function () { return ''; };
      if (typeof p === 'symbol') return undefined;
      if (p === '__pdfmPath') return path;
      if (p === 'toString' || p === 'valueOf') return function () { return ''; };
      if (p === 'length') return 0;
      if (Object.prototype.hasOwnProperty.call(overrides, p)) return overrides[p];
      return __stub(path + '.' + p);
    },
    apply: function (t, self, args) {
      __calls.push([path, Array.prototype.map.call(args, __str)]);
      return __stub(path + '()');
    },
    construct: function (t, args) {
      __calls.push(['new ' + path, Array.prototype.map.call(args, __str)]);
      return __stub(path);
    },
    set: function () { return true; },
    has: function () { return true; }
  });
}
var app = __stub('app', {viewerVersion: 9.0, viewerType: 'Reader', viewerVariation: 'Reader',
                         platform: 'WIN', language: 'ENU', formsVersion: 9.0});
var util = __stub('util'), Collab = __stub('Collab'), media = __stub('media'), spell = __stub('spell'),
    event = __stub('event'), xfa = __stub('xfa'), console = __stub('console'), security = __stub('security'),
    SOAP = __stub('SOAP'), Net = __stub('Net'), identity = __stub('identity'), color = __stub('color'),
    display = __stub('display'), font = __stub('font'), border = __stub('border');
['getAnnots', 'getAnnot', 'exportDataObject', 'importDataObject', 'submitForm', 'getField', 'print',
 'mailDoc', 'getURL', 'launchURL', 'addScript', 'syncAnnotScan', 'getPageNthWord', 'getPageNumWords',
 'closeDoc', 'saveAs', 'getIcon', 'resetForm', 'gotoNamedDest', 'getOCGs', 'getDataObject',
 'getDataObjectContents', 'createDataObject', 'addField', 'removeField', 'getNthFieldName'
].forEach(function (name) { globalThis[name] = __stub('this.' + name); });
var __realEval = eval;
eval = function (s) {
  var code = String(s);
  __evals.push(code.length > %(max_eval)d ? code.slice(0, %(max_eval)d) : code);
  return __realEval(code);
};
var __realUnescape = unescape;
unescape = function (s) {
  var r = __realUnescape(s);
  if (r.length >= 128) __payloads.push(r.slice(0, %(max_payload)d));
  return r;
};
// Any global the emulation lacks (Acrobat built-ins like AFNumber_Keystroke, document methods like
// this.selectPageNthWord) falls through the global object's prototype to a recording stub, instead
// of throwing ReferenceError/TypeError and ending the script early. Real globals are unaffected.
var __base = Object.getPrototypeOf(globalThis);
Object.setPrototypeOf(globalThis, new Proxy(__base, {
  has: function () { return true; },
  get: function (t, p) {
    if (typeof p !== 'string' || p in t) return t[p];
    return __stub(p);
  }
}));
""" % {"max_eval": MAX_EVAL_CAPTURE, "max_payload": MAX_PAYLOAD_CAPTURE // 2}


@dataclass
class ScriptRun:
    status: str  # "ok", "error: ...", "timeout", "memory limit"
    calls: list[str] = field(default_factory=list)  # "Collab.getIcon(\"N.x\")"
    evals: list[str] = field(default_factory=list)  # code passed to eval()
    payloads: list[bytes] = field(default_factory=list)  # large unescape() results, as bytes in memory


def available() -> bool:
    return MiniRacer is not None


def run_scripts(codes: list[str], doc_info: dict[str, str]) -> list[ScriptRun]:
    """Run scripts in order in one context, like a reader running a document's scripts."""
    ctx = MiniRacer()
    ctx.set_hard_memory_limit(MEMORY_LIMIT)
    runs = []
    try:
        ctx.eval(PRELUDE)
        # json.dumps output is a valid JS literal; the info dict holds attacker-controlled strings,
        # so it is passed as data, never concatenated into code.
        ctx.eval("var info = %s; globalThis.info = info;" % json.dumps(doc_info))
        for code in codes:
            before = _counts(ctx)
            status = "ok"
            try:
                ctx.eval(code, timeout_sec=SCRIPT_TIMEOUT)
            except JSTimeoutException:
                status = "timeout"
            except JSEvalException as exc:
                status = "memory limit" if ctx.was_hard_memory_limit_reached() else \
                    "error: " + str(exc).splitlines()[0][:200]
            runs.append(_collect(ctx, before, status))
            if status == "memory limit":
                break  # the isolate is unreliable after hitting the hard limit
    finally:
        ctx.close()
    return runs


def _counts(ctx) -> tuple[int, int, int]:
    try:
        return tuple(json.loads(ctx.eval("JSON.stringify([__calls.length, __evals.length, __payloads.length])")))
    except Exception:
        return (0, 0, 0)


def _collect(ctx, before: tuple[int, int, int], status: str) -> ScriptRun:
    run = ScriptRun(status)
    try:
        calls, evals, payloads = json.loads(ctx.eval(
            "JSON.stringify([__calls.slice(%d), __evals.slice(%d), __payloads.slice(%d)])" % before))
    except Exception:
        return run
    # Values come from hostile code: never assume they're strings.
    run.calls = [f"{path}({', '.join(str(a) for a in args)})" for path, args in calls]
    run.evals = [e for e in evals if isinstance(e, str)]
    run.payloads = [p.encode("utf-16-le", "surrogatepass") for p in payloads if isinstance(p, str)]
    return run
