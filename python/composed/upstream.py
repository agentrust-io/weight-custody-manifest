"""Synthetic JSON-RPC tool; records receipt separately from the controller."""
import json
import sys
from pathlib import Path

for line in sys.stdin:
    request = json.loads(line)
    if request['method'] == 'tools/list':
        result = {'tools': [{'name': name, 'description': 'record synthetic data',
                           'inputSchema': {'type': 'object'}}
                          for name in ('permitted.tool', 'public.tool')]}
    elif request['method'] == 'tools/call':
        with Path(sys.argv[1]).open('a', encoding='utf-8') as sink:
            sink.write(json.dumps(request['params']) + '\n')
        result = {'content': [{'type': 'text', 'text': request['params']['arguments']['value']}]}
    else:
        result = {}
    if 'id' in request:
        print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
