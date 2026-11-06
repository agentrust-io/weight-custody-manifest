"""External H100 adapter validation; no hardware attack or attestation claim."""
import hashlib

import pytest
import torch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from wcm._seal import generate_transport_keypair
from wcm._signing import _b64url_encode
from wcm._types import HashValue
from wcm.model_memory import (BufferMemoryReader, ModelMemoryBaseline,
    ModelMemoryError, ModelMemoryGuard, ModelMemoryVerifier,
    measure_model_buffers, observe_model_memory)

assert torch.cuda.is_available(), 'Real CUDA is required; no skip or CPU fallback'

def h(data):
    return HashValue('sha256:' + hashlib.sha256(data).hexdigest())

class CudaReader:
    def __init__(self, tensor):
        if not tensor.is_cuda or not tensor.is_contiguous():
            raise ValueError('requires contiguous actual CUDA storage')
        self.tensor = tensor
    @property
    def nbytes(self):
        return self.tensor.numel() * self.tensor.element_size()
    def read(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.nbytes:
            raise ValueError('out of range')
        torch.cuda.synchronize(self.tensor.device)
        return bytes(self.tensor.view(torch.uint8).reshape(-1)[offset:offset+length].cpu().tolist())

def make_baseline(expected):
    return ModelMemoryBaseline(manifest_hash=h(b'fixture-manifest'),
        weights_hash=h(b'fixture-package'), serving_image_measurement=h(b'fixture-observer'),
        layout_id='cuda-validation-v1', buffers=measure_model_buffers(expected))

@pytest.mark.parametrize('dtype', [torch.float16, torch.bfloat16, torch.float32, torch.int8])
def test_actual_cuda_storage_and_independent_baseline(dtype):
    cpu = torch.arange(1024, dtype=torch.float32).remainder(17).to(dtype).reshape(32,32)
    expected = bytes(cpu.view(torch.uint8).reshape(-1).tolist())
    gpu = cpu.cuda()
    reader = CudaReader(gpu)
    baseline = make_baseline({'weight': BufferMemoryReader(expected)})
    stops = []
    guard = ModelMemoryGuard(baseline, on_failure=lambda: stops.append('stop'))
    guard.check_before_operation({'weight':reader})
    good = gpu.float().sum().item()
    gpu[0,0] = 32
    torch.cuda.synchronize()
    assert gpu.float().sum().item() != good
    with pytest.raises(ModelMemoryError):
        guard.check_before_operation({'weight':reader})
    gpu[0,0] = 0
    with pytest.raises(ModelMemoryError):
        guard.check_before_operation({'weight':reader})
    assert stops == ['stop']
    assert bytes(cpu.view(torch.uint8).reshape(-1).tolist()) == expected

@pytest.mark.parametrize('position', [0, 1048575, 1048576, 3145744])
def test_chunk_boundary_mutations(position):
    size = 3*1024*1024+17
    expected = bytes(size)
    tensor = torch.zeros(size, device='cuda', dtype=torch.uint8)
    baseline = make_baseline({'weight':BufferMemoryReader(expected)})
    buffers = {'weight':CudaReader(tensor)}
    ModelMemoryGuard(baseline, on_failure=lambda: None).check_before_operation(buffers)
    tensor[position] = 1
    with pytest.raises(ModelMemoryError):
        ModelMemoryGuard(baseline, on_failure=lambda: None).check_before_operation(buffers)

def test_gpu_and_cpu_spill_inventory_and_signed_challenge():
    expected_gpu = bytes(8192)
    cpu_spill = bytearray(4096)
    gpu = torch.zeros(8192, device='cuda', dtype=torch.uint8)
    baseline = make_baseline({'gpu.weight':BufferMemoryReader(expected_gpu),
                             'cpu.spill':BufferMemoryReader(bytes(cpu_spill))})
    buffers = {'gpu.weight':CudaReader(gpu), 'cpu.spill':BufferMemoryReader(cpu_spill)}
    key = Ed25519PrivateKey.generate()
    _, transport = generate_transport_keypair()
    verifier = ModelMemoryVerifier(baseline=baseline, transport_public_key=transport,
        observer_public_key_b64url=_b64url_encode(key.public_key().public_bytes_raw()))
    def sample():
        nonce = verifier.issue_challenge().nonce
        return observe_model_memory(buffers, baseline=baseline, challenge_nonce=nonce,
            transport_public_key=transport, signing_key=key), nonce
    observation, nonce = sample()
    assert verifier.verify(observation, challenge_nonce=nonce)[0]
    assert not verifier.verify(observation, challenge_nonce=nonce)[0]
    cpu_spill[7] = 42
    observation, nonce = sample()
    assert not verifier.verify(observation, challenge_nonce=nonce)[0]
    cpu_spill[7] = 0
    gpu[4000] = 42
    observation, nonce = sample()
    assert not verifier.verify(observation, challenge_nonce=nonce)[0]
    gpu[4000] = 0
    del buffers['cpu.spill']
    observation, nonce = sample()
    assert not verifier.verify(observation, challenge_nonce=nonce)[0]

def test_reject_noncontiguous_device_adapter():
    tensor = torch.zeros((8,8), device='cuda').transpose(0,1)
    with pytest.raises(ValueError):
        CudaReader(tensor)

def test_post_sample_change_is_not_detected_by_old_report():
    tensor = torch.zeros(32, device='cuda', dtype=torch.uint8)
    baseline = make_baseline({'weight':BufferMemoryReader(bytes(32))})
    buffers = {'weight':CudaReader(tensor)}
    key = Ed25519PrivateKey.generate()
    _, transport = generate_transport_keypair()
    verifier = ModelMemoryVerifier(baseline=baseline, transport_public_key=transport,
        observer_public_key_b64url=_b64url_encode(key.public_key().public_bytes_raw()))
    nonce = verifier.issue_challenge().nonce
    old = observe_model_memory(buffers, baseline=baseline, challenge_nonce=nonce,
        transport_public_key=transport, signing_key=key)
    tensor[0] = 1
    torch.cuda.synchronize()
    assert verifier.verify(old, challenge_nonce=nonce)[0]  # point-in-time evidence
    with pytest.raises(ModelMemoryError):
        ModelMemoryGuard(baseline, on_failure=lambda: None).check_before_operation(buffers)
