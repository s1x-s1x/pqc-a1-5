#!/usr/bin/env python3
"""Prepare r3 freeze commands and byte evidence. Never starts a timing worker.

commands only prints shell commands; archives/readiness/external perform byte,
JSON, archive and runtime-provenance checks. Run on the accepted Linux host.
This helper is outside the frozen application/tool source set.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace
from unittest.mock import patch

BASE = Path('/home/guest-experiment/pqc-a1-5')
STAGE = BASE / 'build/repair-staging-20261004-r3'

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()

def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def write(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        f.write(json.dumps(obj, indent=2, ensure_ascii=False) + '\n')

def verify_sources(stage, sources):
    require(isinstance(sources, dict) and sources, 'empty tested source map')
    for name, digest in sources.items():
        p = PurePosixPath(name)
        require(not p.is_absolute() and '..' not in p.parts and str(p) == name,
                'noncanonical source path')
        require(sha(stage / name) == digest, 'tested source changed: ' + name)
    require('c/Makefile' in sources and 'c/src/secure_zero.h' in sources,
            'repair build identity omitted')

def verify_archive(path, sources):
    with tarfile.open(path, 'r:gz') as bundle:
        members = bundle.getmembers()
        require(all(m.isfile() and not m.issym() and not m.islnk() for m in members),
                'archive has nonregular members')
        require(len(members) == len(sources) and {m.name for m in members} == set(sources),
                'archive exact members differ')
        for m in members:
            with bundle.extractfile(m) as f:
                require(hashlib.sha256(f.read()).hexdigest() == sources[m.name],
                        'archive bytes differ: ' + m.name)

def add_archive(stage, directory, sources, *, native=False):
    verify_sources(stage, sources)
    archive = directory / ('source.tar.gz' if native else 'tested-source.tar.gz')
    record = directory / ('source-archive.json' if native else 'tested-source.json')
    if archive.exists() or record.exists():
        require(archive.is_file() and record.is_file(), 'partial archive pair already exists')
        verify_archive(archive, sources)
        expected = ({'source_archive_sha256': sha(archive),
                     'manifest_sha256': sha(directory / 'manifest.json')} if native else
                    {'sources_sha256': sources, 'archive_sha256': sha(archive)})
        require(read(record) == expected, 'existing archive record differs')
        return
    with tarfile.open(archive, 'x:gz') as bundle:
        for name in sorted(sources):
            bundle.add(stage / name, arcname=name, recursive=False)
    verify_archive(archive, sources)
    verify_sources(stage, sources)
    write(record, ({'source_archive_sha256': sha(archive),
                    'manifest_sha256': sha(directory / 'manifest.json')} if native else
                   {'sources_sha256': sources, 'archive_sha256': sha(archive)}))

def archives(args):
    stage = args.stage.resolve()
    n = stage / 'validation/native-repair-r3'
    c = stage / 'validation/cpu-full-repair-r3'
    native, full = read(n / 'manifest.json'), read(c / 'summary.json')
    require(native['passed'] and native['source_unchanged'] and native['inputs_unchanged'],
            'current native acceptance pending')
    require(len(native['steps']) == 11 and all(s['returncode'] == 0 for s in native['steps']),
            'current native eleven steps differ')
    require(full['passed'] and full['final'] and full['completed_requested_scope'] and
            full['suite'] == 'full' and full['full_sha2'] and not full['deferred_scope'] and
            full['planned_cases'] == full['passed_planned'] == 3471 and
            not full['formal_performance_started'] and not full['measured_durations'],
            'current full CPU acceptance pending')
    require(sha(c / 'cases.jsonl') == full['cases_jsonl_sha256'], 'CPU full JSONL changed')
    for group in ('inputs_sha256', 'evidence_sha256', 'build_sha256'):
        for path, digest in native[group].items():
            require(sha(stage / path) == digest, 'native evidence changed: ' + path)
    accepted = {digest for path, digest in native['build_sha256'].items()
                if path.endswith('/counters/libslhdsa_sm3.so')}
    require(accepted and all(v['sha256'] in accepted and sha(v['path']) == v['sha256']
                            for v in full['libraries'].values()), 'native/current full library mismatch')
    add_archive(stage, n, native['source_sha256'], native=True)
    add_archive(stage, c, full['source_hashes'])
    print(json.dumps({'passed': True, 'archive_pairs': 2, 'native_calls': 0,
                      'real_timing_samples': 0}))

def layout(stage):
    p = stage / 'preparation/final-freeze-r3'
    return {'prep': p, 'cpu': stage / 'build/bench-cpu-repair-r3-release',
            'cuda': stage / 'build/bench-cuda-repair-r3-release',
            'cpu_pkg': stage / 'validation/optimization-cpu-repair-r3-final',
            'cuda_pkg': stage / 'validation/optimization-cuda-repair-r3-final'}

def commands(args):
    # Shell suggestions are POSIX paths even when generated on Windows.
    s, py = PurePosixPath(args.stage.as_posix()), PurePosixPath(args.python.as_posix())
    d = layout(s)
    c, g, p = d['cpu'], d['cuda'], d['prep']
    n, f = s / 'validation/native-repair-r3', s / 'validation/cpu-full-repair-r3'
    gn, gf = s / 'validation/cuda-native-repair-r3', s / 'validation/cuda-full-repair-r3'
    emit = lambda argv: print(shlex.join([str(x) for x in argv]))
    print('# Suggested sequence only; this action executes no commands.')
    print('set -euo pipefail')
    print('export CUDA_VISIBLE_DEVICES=0 OMP_DYNAMIC=FALSE')
    emit(['cd', s])
    emit(['mkdir', '-p', p])
    emit([py, 'tools/bench_cpu.py', 'build', '--out', c, '--cc', args.cc, '--cflags=-O3'])
    emit([py, 'tools/check_rng_native.py', '--library', s / 'build/native-repair-r3/avx2/libslhdsa_sm3.so',
          '--backend', 'avx2', '--output', n / 'rng.json'])
    emit([py, 'tools/bench_cpu.py', 'self-test', '--output', p / 'cpu-mock.json'])
    binary = p / 'bench_sm3_harness'
    compile = [args.cc, '-std=c11', '-O3', '-Wall', '-Wextra', '-Ic/src',
               'tools/bench_sm3_harness.c', 'c/src/sm3.c', 'c/src/sm3x8.c', '-o', str(binary)]
    emit(compile)
    emit([py, 'tools/bench_cpu.py', 'sm3-check', '--binary', binary, '--cc', args.cc,
          '--build-command', shlex.join(compile), '--output', p / 'sm3-correctness.json'])
    print('# Add current tested-source/native archive pairs before CUDA freeze.')
    emit([py, args.helper_path, 'archives', '--stage', s])
    emit([py, 'tools/freeze_optimization.py', '--native-run', n, '--matrix-run', f,
          '--build-record', c / 'build-record.json', '--mock-record', p / 'cpu-mock.json',
          '--sm3-correctness', p / 'sm3-correctness.json',
          '--plan', 'docs/bench_cpu/R3.plan.json', '--plan', 'docs/bench_cpu/R4.plan.json',
          '--plan', 'docs/bench_cpu/R5.pow2.plan.json', '--output-dir', d['cpu_pkg']])
    emit([py, 'tools/bench_cuda.py', 'build', '--out', g, '--cc', args.cc,
          '--nvcc', args.nvcc, '--host-cxx', args.host_cxx, '--arch', 'sm_86'])
    emit([py, 'tools/bench_cuda.py', 'self-test', '--output', p / 'cuda-mock.json'])
    print('BUDGET_DB=$(' + shlex.join([str(py), '-c',
          'import json,sys;print(json.load(open(sys.argv[1]))["identity"]["budget_database_path"])',
          str(gf / 'summary.json')]) + ')')
    print('CUDA_VISIBLE_DEVICES=0 OMP_DYNAMIC=FALSE ' + shlex.join([str(py), 'tools/check_cuda_release.py',
          '--library', str(g / 'libslhdsa_sm3.so'), '--build-record', str(g / 'build-record.json'),
          '--vectors', str(s / 'reference/evidence/python-sm3-128-24.jsonl'), '--threads', '64']) +
          ' --budget-db "$BUDGET_DB" --output ' + shlex.quote(str(p / 'cuda-release14.json')))
    emit([py, 'tools/check_rng_native.py', '--library', g / 'libslhdsa_sm3.so', '--backend', 'cuda',
          '--output', p / 'cuda-cli-rng.json'])
    emit([py, 'tools/freeze_cuda.py', '--cuda-run', gf, '--native-run', gn,
          '--cpu-baseline-run', n, '--kernel-record', gn / 'kernel.json',
          '--release-correctness', p / 'cuda-release14.json', '--cli-correctness', p / 'cuda-cli-rng.json',
          '--build-record', g / 'build-record.json', '--mock-record', p / 'cuda-mock.json',
          '--plan', 'docs/bench_cuda/CUDA_B1.v2.plan.json', '--output-dir', d['cuda_pkg']])
    emit([py, args.helper_path, 'readiness', '--stage', s])
    emit([py, args.helper_path, 'external', '--stage', s])

def readiness(args):
    s, d = args.stage.resolve(), layout(args.stage.resolve())
    sys.path.insert(0, str(s / 'tools'))
    import bench_cpu as cpu
    import bench_cuda as cuda
    packages = {}
    def blocked(*a, **k):
        raise AssertionError('readiness prohibits native loads and performance timers')
    with ExitStack() as stack:
        stack.enter_context(patch.object(cpu, 'NativeSlhDsa', side_effect=blocked))
        stack.enter_context(patch.object(cuda, 'NativeSlhDsa', side_effect=blocked))
        stack.enter_context(patch('ctypes.CDLL', side_effect=blocked))
        stack.enter_context(patch('time.perf_counter', side_effect=blocked))
        stack.enter_context(patch('time.perf_counter_ns', side_effect=blocked))
        for kind in ('cpu', 'cuda'):
            pkg = d[kind + '_pkg']
            freeze, package = read(pkg / 'freeze.json'), read(pkg / 'package.json')
            cpu.validate_published_freeze(pkg / 'freeze.json', freeze)
            sources = read(pkg / 'source-manifest.json')
            verify_archive(pkg / 'source.tar.gz', sources)
            for name, digest in freeze['source_sha256'].items():
                require(sha(s / name) == digest, 'current freeze source differs: ' + name)
            mock = read(d['prep'] / (kind + '-mock.json'))
            require(mock['passed'] and mock['native_calls'] == mock['real_timing_samples'] == 0,
                    'mock final state differs')
            field = 'correctness_evidence' if kind == 'cpu' else 'correctness_evidence_sha256'
            packages[kind] = dict(passed=True, directory=str(pkg), source_files=len(sources),
                 evidence_files=len(freeze[field]), freeze_sha256=sha(pkg / 'freeze.json'),
                 package_sha256=sha(pkg / 'package.json'), files_sha256=package['files_sha256'],
                 mock_checks=mock['mock_checks'], real_timing_samples=0)
        a = SimpleNamespace(library=d['cpu'] / 'libslhdsa_sm3.so', build_record=d['cpu'] / 'build-record.json',
                            freeze=d['cpu_pkg'] / 'freeze.json')
        prov = cpu.provenance(a)
        require(prov['final'], 'CPU runtime provenance gate incomplete')
        for name in ('R3.plan.json', 'R4.plan.json', 'R5.pow2.plan.json'):
            p = s / 'docs/bench_cpu' / name
            cpu.validate_frozen_plan(read(p), sha(p), prov)
        a = SimpleNamespace(library=d['cuda'] / 'libslhdsa_sm3.so', build_record=d['cuda'] / 'build-record.json',
                            freeze=d['cuda_pkg'] / 'freeze.json', plan=s / 'docs/bench_cuda/CUDA_B1.v2.plan.json')
        permit = cuda.validate_freeze(a)
        require(permit['formal_gate_passed'] and permit['real_timing_samples'] == 0,
                'CUDA runtime provenance gate incomplete')
    active = []
    process_rows = subprocess.check_output(['ps', '-u', str(os.getuid()), '-o', 'pid=,args='], text=True)
    for row in process_rows.splitlines():
        if re.search(r'(?:^|\s)(?:\S+/)?bench_(?:cpu|cuda)\.py\s+(?:run|worker|smoke)(?:\s|$)', row):
            active.append(row.strip())
    require(not active, 'active performance process exists')
    perf = []
    for path in sorted(s.rglob('*.jsonl')):
        for line in path.read_text(encoding='utf-8').splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and row.get('schema') in ('a15-cpu-bench-v1', 'a15-cuda-bench-v1'):
                perf.append(str(path)); break
    require(not perf, 'performance campaign JSONL exists')
    record = dict(schema='a15-optimization-final-readiness-v1', passed=True,
         created_utc=datetime.now(timezone.utc).isoformat(), packages=packages,
         cpu_gate_passed=True, cuda_gate_passed=True, real_native_calls=0, real_timing_samples=0,
         formal_performance_started=False, active_benchmark_processes=[], performance_jsonl_files=[],
         stopping_point='current r3 full acceptance and CPU/CUDA freeze; performance not started')
    output = args.output or s / 'validation/repair-final-readiness-r3.json'
    write(output, record)
    print(json.dumps({'passed': True, 'output': str(output), 'real_timing_samples': 0}))

def external(args):
    s, d = args.stage.resolve(), layout(args.stage.resolve())
    expected = {}
    for kind in ('cpu', 'cuda'):
        f = read(d[kind + '_pkg'] / 'freeze.json')
        field = 'correctness_evidence' if kind == 'cpu' else 'correctness_evidence_sha256'
        for name, digest in f[field].items():
            if name.startswith(str(BASE) + '/'):
                continue
            require(name.startswith('/') and '..' not in PurePosixPath(name).parts,
                    'external path is noncanonical')
            require(name not in expected or expected[name] == digest, 'external hash disagreement')
            expected[name] = digest
    require(expected, 'external frozen evidence set is empty')
    entries = {}
    for name, digest in sorted(expected.items()):
        require(sha(name) == digest, 'external frozen dependency changed: ' + name)
        relative = 'validation/optimization-external-evidence/' + name.lstrip('/')
        entries[name] = dict(local_path=relative, sha256=digest, size_bytes=Path(name).stat().st_size)
        dest = s / relative
        if dest.exists():
            require(dest.is_file() and sha(dest) == digest and dest.stat().st_size == entries[name]['size_bytes'],
                    'existing mirror bytes differ')
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with Path(name).open('rb') as source, dest.open('xb') as target:
                shutil.copyfileobj(source, target, 1048576)
            require(sha(dest) == digest, 'copied external bytes differ')
    out = args.output or s / 'validation/repair-external-evidence-r3-manifest.json'
    write(out, dict(schema='a15-external-evidence-mirror-v1',
         created_utc=datetime.now(timezone.utc).isoformat(), remote_project_root=str(s), files=entries,
         classification='original Linux external bytes for repair local mirror audit; native/performance 0'))
    print(json.dumps({'passed': True, 'manifest': str(out), 'external_files': len(entries),
                      'native_calls': 0, 'real_timing_samples': 0}))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('commands', 'archives', 'readiness', 'external'))
    p.add_argument('--stage', type=Path, default=STAGE)
    p.add_argument('--python', type=Path, default=BASE / '.venv/bin/python')
    p.add_argument('--helper-path', default='preparation/final-freeze-r3.py')
    p.add_argument('--cc', default='gcc')
    p.add_argument('--nvcc', default='nvcc')
    p.add_argument('--host-cxx', default='g++')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    {'commands': commands, 'archives': archives, 'readiness': readiness, 'external': external}[args.action](args)

if __name__ == '__main__':
    main()
