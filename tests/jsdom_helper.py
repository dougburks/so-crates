#!/usr/bin/env python3
"""Helper for running JavaScript tests in a JSDOM environment.

This module provides a way to execute socrates.js functions in a Node.js/JSDOM
context from Python unit tests, enabling behavioral testing instead of
brittle string-grep tests.
"""

import json
import os
import subprocess
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
HTML_PATH = os.path.join(PROJECT_ROOT, 'socrates.html')
JS_PATH = os.path.join(PROJECT_ROOT, 'static', 'socrates.js')
CSS_PATH = os.path.join(PROJECT_ROOT, 'static', 'socrates.css')
D3_PATH = os.path.join(PROJECT_ROOT, 'static', 'd3.min.js')
D3_SANKEY_PATH = os.path.join(PROJECT_ROOT, 'static', 'd3-sankey.min.js')
NODE_MODULES = os.path.join(PROJECT_ROOT, 'node_modules')

# JSDOM's page origin for every test - deliberately NOT the app's real,
# documented dev-server port (8000, see docker-compose's "8000:8000" mapping
# and README) so a developer running `python3 socrates.py` while the suite
# is also running can't collide with it. See the 'usable' resources loader
# comment below for what that collision used to cause.
JSDOM_TEST_ORIGIN = 'http://localhost:19999'


def load_files():
    """Load HTML, JS, and CSS content."""
    with open(HTML_PATH, 'r') as f:
        html = f.read()
    with open(JS_PATH, 'r') as f:
        js = f.read()
    with open(CSS_PATH, 'r') as f:
        css = f.read()
    return html, js, css


def load_d3():
    """Load d3 and d3-sankey source (UMD builds); d3 must eval before d3-sankey
    since d3-sankey extends the same global `d3` object d3.min.js creates."""
    with open(D3_PATH, 'r') as f:
        d3 = f.read()
    with open(D3_SANKEY_PATH, 'r') as f:
        d3_sankey = f.read()
    return d3, d3_sankey


def run_jsdom_test(js_test_code, setup_code='', with_d3=False):
    """Execute JS test code in a JSDOM environment with socrates loaded.

    Args:
        js_test_code: The JS code to evaluate. Must assign its result to window.__jsdom_result.
        setup_code: Optional JS code to run before the test.
        with_d3: If True, also load d3.min.js and d3-sankey.min.js before
            socrates.js (needed only for tests exercising renderSankeySVG).

    Returns:
        The parsed JSON result from the JS execution.

    Raises:
        RuntimeError: If the JS execution fails or returns invalid JSON.
    """
    html, js, css = load_files()
    d3_load_snippet = ''
    if with_d3:
        d3, d3_sankey = load_d3()
        d3_load_snippet = f'''
window.eval({json.dumps(d3)});
window.eval({json.dumps(d3_sankey)});
'''

    # Build the Node.js script
    node_script = f'''
const {{ JSDOM, requestInterceptor }} = require('jsdom');
const fs = require('fs');
const path = require('path');

const htmlContent = {json.dumps(html)};
const jsContent = {json.dumps(js)};
const cssContent = {json.dumps(css)};

// Serves static/* from disk instead of over the network. Without this,
// anything that triggers a real subresource fetch (e.g. an iframe
// navigating via srcdoc with a <link rel=stylesheet href="static/...">,
// as the theme preview iframe does) hangs the whole node process forever:
// nothing is listening on the {JSDOM_TEST_ORIGIN} base URL in this
// offline test environment, so the pending request keeps the event loop
// alive indefinitely and the script never exits on its own.
const staticFileInterceptor = requestInterceptor(async (request) => {{
    let pathname;
    try {{
        pathname = new URL(request.url).pathname;
    }} catch (e) {{
        return undefined;
    }}
    if (!pathname.startsWith('/static/')) return undefined;
    const localPath = path.join(process.cwd(), pathname);
    if (!fs.existsSync(localPath)) return undefined;
    const contentType = pathname.endsWith('.css') ? 'text/css'
        : pathname.endsWith('.js') ? 'application/javascript'
        : 'application/octet-stream';
    return new Response(fs.readFileSync(localPath), {{ headers: {{ 'Content-Type': contentType }} }});
}});

const dom = new JSDOM(htmlContent, {{
    runScripts: 'dangerously',
    url: {json.dumps(JSDOM_TEST_ORIGIN)},
    pretendToBeVisual: true,
    resources: 'usable',
    interceptors: [staticFileInterceptor]
}});

const window = dom.window;
const document = window.document;

// Mock fetch before loading JS (prevents init() from failing)
window.fetch = function() {{ return Promise.resolve({{ json: () => Promise.resolve([]) }}); }};

// Inject CSS into the DOM
const styleEl = document.createElement('style');
styleEl.textContent = cssContent;
document.head.appendChild(styleEl);

// Make globals available
window.document = document;

// jsdom does not implement Element.prototype.scrollIntoView at all (it's
// simply undefined, not a no-op) - every real browser has always had it as
// a standard, always-present method that never throws under normal use, so
// its absence here is purely a jsdom gap, not something socrates.js's own
// code needs to guard against. Without this shim, any keyboard-navigation
// function that calls .scrollIntoView() (there are several) throws
// partway through - and since that throw happens inside a keydown event
// listener, jsdom/the DOM spec swallows it silently rather than
// propagating it to the dispatchEvent() call site, so test code sees no
// error at all, just seemingly-inexplicable missing side effects from
// whatever the function was supposed to do AFTER its scrollIntoView call.
window.Element.prototype.scrollIntoView = window.Element.prototype.scrollIntoView || function() {{}};

// Optionally load d3 / d3-sankey (order matters: d3 first) before socrates.js
{d3_load_snippet}

// Run the main JS file via window.eval
window.eval(jsContent);

// Run setup code in window context if provided
{setup_code}

// Run the test code in window context and capture result. The test code is
// wrapped in an async IIFE so it may itself use `await` (many socrates.js
// functions are async - e.g. buildSection, applyFilters), and the outer
// script awaits that IIFE before reading the result, so assignments to
// window.__jsdom_result made after an awaited call are not missed.
// The test code must still assign its result to window.__jsdom_result.
(async () => {{
    try {{
        await window.eval({json.dumps('(async () => {' + js_test_code + '})()')});
    }} catch(e) {{
        window.__jsdom_result = {{__jsdom_error: e.message, __jsdom_stack: e.stack}};
    }}
    const __jsdom_result = window.__jsdom_result;
    delete window.__jsdom_result;

    // Handle undefined and other non-JSON values
    if (__jsdom_result === undefined) {{
        console.log(JSON.stringify({{__jsdom_undefined: true}}));
    }} else {{
        console.log(JSON.stringify(__jsdom_result));
    }}

    // Force exit once the result is captured, rather than waiting for
    // Node's event loop to drain naturally. jsdom's "resources: usable"
    // subresource loader (e.g. the theme preview iframe navigating via
    // srcdoc with a real <link rel=stylesheet>) can leave a pending
    // request in flight against {JSDOM_TEST_ORIGIN} - nothing is
    // listening there in this offline test environment, so without a
    // forced exit the process hangs indefinitely even though the test
    // itself already finished and produced its result above.
    process.exit(0);
}})();
'''

    env = os.environ.copy()
    env['NODE_PATH'] = NODE_MODULES

    # Write script to temp file (avoids "Argument list too long" error).
    # System temp dir, not PROJECT_ROOT: a hard-killed test run would
    # otherwise strand ~840KB tmp*.js orphans in the repo root.
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(node_script)
        script_path = f.name

    try:
        result = subprocess.run(
            ['node', script_path],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
            env=env
        )
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass

    if result.returncode != 0:
        raise RuntimeError(f'JSDOM test failed: {result.stderr}')

    output = result.stdout.strip()
    if not output:
        raise RuntimeError('JSDOM test returned empty output')

    try:
        parsed = json.loads(output)
    except json.JSONDecodeError as e:
        raise RuntimeError(f'JSDOM test returned invalid JSON: {output[:200]}... Error: {e}')

    if isinstance(parsed, dict):
        if '__jsdom_error' in parsed:
            raise RuntimeError(f'JSDOM JS error: {parsed["__jsdom_error"]}')
        if '__jsdom_undefined' in parsed:
            return None

    return parsed


def js_expression(expr, setup_code='', with_d3=False):
    """Evaluate a JS expression and return the result.

    Args:
        expr: A single JS expression (no statements) that evaluates to a JSON-serializable value.
        setup_code: Optional setup JS code.
        with_d3: If True, also load d3/d3-sankey before socrates.js.

    Returns:
        The parsed JSON result.
    """
    js_code = f'window.__jsdom_result = {expr};'
    return run_jsdom_test(js_code, setup_code, with_d3=with_d3)


def js_statements(code, setup_code='', with_d3=False):
    """Execute JS statements and return the value assigned to window.__jsdom_result.

    Args:
        code: JS statements. Must assign the result to window.__jsdom_result.
        setup_code: Optional setup JS code.
        with_d3: If True, also load d3/d3-sankey before socrates.js.

    Returns:
        The parsed JSON result.
    """
    return run_jsdom_test(code, setup_code, with_d3=with_d3)
