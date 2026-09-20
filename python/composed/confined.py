"""Confined mediation adapter. Reuses the pinned cMCP supervisor unchanged."""
import asyncio
import json
import os
from contextlib import asynccontextmanager

from composed.gateway import make_gateway


@asynccontextmanager
async def observers():
    received = {'tcp': [], 'tcp6': [], 'udp': []}

    async def tcp(reader, writer, kind):
        received[kind].append(await reader.read(4096))
        writer.close()
        await writer.wait_closed()

    class UDP(asyncio.DatagramProtocol):
        def datagram_received(self, data, address):
            received['udp'].append(data)

    v4 = await asyncio.start_server(lambda r, w: tcp(r, w, 'tcp'), '127.0.0.1', 0)
    v6 = await asyncio.start_server(lambda r, w: tcp(r, w, 'tcp6'), '::1', 0)
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(UDP, local_addr=('127.0.0.1', 0))
    try:
        yield received, {'tcp': v4.sockets[0].getsockname()[1],
                         'tcp6': v6.sockets[0].getsockname()[1],
                         'udp': udp.get_extra_info('sockname')[1]}
    finally:
        v4.close()
        v6.close()
        await v4.wait_closed()
        await v6.wait_closed()
        udp.close()


def require_isolation(observed):
    assert observed['network'] == {'tcp': 0, 'tcp6': 0, 'udp': 0}
    assert not observed['file']
    assert not observed['logs']
    assert not observed['running']
    assert observed['public_calls'] == 0


def confined_mediator(monkeypatch, observed, mutation=None):
    from examples.confinement import adapter

    async def mediate(sink, payload, tool):
        sandbox = adapter.DockerSandbox(os.environ['COMPOSED_AGENT_IMAGE'])
        proxy, dispatch = make_gateway(sink)
        permitted = []
        public = []

        async def route(name, args):
            result = await dispatch(name, args)
            if result['allowed']:
                (permitted if name == 'permitted.tool' else public).append(result)
            return result

        if mutation:
            original = adapter.verify_container
            flag, replacement = {
                'network': ('--network=none', '--network=host'),
                'filesystem': ('--read-only', None),
                'logging': ('--log-driver=none', '--log-driver=json-file'),
            }[mutation]
            sandbox.arguments.remove(flag)
            if replacement:
                sandbox.arguments.insert(1, replacement)

            def weakened(info):
                # First prove the normal admission gate catches the changed profile.
                try:
                    original(info)
                except adapter.Refused:
                    return
                raise AssertionError('profile weakening escaped normal admission')

            monkeypatch.setattr(adapter, 'verify_container', weakened)
        created = False
        try:
            await sandbox.create()
            created = True
            async with observers() as (received, addresses):
                stats = await sandbox.execute({'payload': payload.decode(), **addresses}, route,
                                               {'permitted': 'permitted.tool', 'public': 'public.tool'})
                info = json.loads(await sandbox.docker('inspect', sandbox.name))[0]
                try:
                    file_bytes = await sandbox.docker('cp', sandbox.name + ':/export/leak.txt', '-')
                except adapter.Refused:
                    # Inspect above has established that the stopped container exists.
                    file_bytes = b''
                logger = await asyncio.create_subprocess_exec(*sandbox.command, 'logs', sandbox.name,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                logs, _ = await asyncio.wait_for(logger.communicate(), 10)
                if logger.returncode and info['HostConfig']['LogConfig']['Type'] != 'none':
                    raise AssertionError('log observation failed')
                observed.update(network={key: sum(payload in value for value in values)
                                         for key, values in received.items()},
                                file=payload in file_bytes, logs=payload in logs,
                                running=info['State']['Running'], public_calls=len(public),
                                stats=stats, image=os.environ['COMPOSED_AGENT_IMAGE'])
            assert len(permitted) == 1
            return permitted[0]
        finally:
            await proxy.aclose()
            if created:
                await sandbox.remove()

    return mediate
