"""Local Linux handoff/scheduler; preserves serial evidence and live budget."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path('/home/guest-experiment/pqc-a1-5/build/repair-staging-20261004-r3')
CPU = ROOT / 'validation/cpu-full-repair-r3'
HISTORY = ROOT / 'validation/cpu-full-repair-r3-serial-history'
WORK = ROOT / 'validation/parallel-correctness-r3'
BUDGET = ROOT / 'validation/repair-pipeline/correctness-budget.sqlite'
PIDS = (2309718, 2734366, 2734374)

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        f.write(json.dumps(value, indent=2) + '\n')

def alive(pid):
    path = Path('/proc') / str(pid) / 'stat'
    return path.exists() and path.read_text().split(') ', 1)[1][0] != 'Z'

def run(args, **kwargs):
    subprocess.run([sys.executable, *args], cwd=ROOT, check=True, **kwargs)

def physical_cpus():
    rows = subprocess.check_output(['lscpu', '-p=CPU,CORE,SOCKET'], text=True)
    found = {}
    permitted = os.sched_getaffinity(0)
    for row in rows.splitlines():
        if row.startswith('#'):
            continue
        cpu, core, socket = map(int, row.split(','))
        if cpu in permitted:
            found.setdefault((socket, core), cpu)
    return sorted(found.values())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--core-budget', type=int, default=96)
    parser.add_argument('--max-workers', type=int, default=16)
    args = parser.parse_args()
    os.chdir(ROOT)
    if HISTORY.exists() or WORK.exists():
        raise ValueError('Handoff outputs already exist; preserve before recovery')
    acceptance=json.loads((ROOT/'build/repair-delivery-tools/parallel-regression/selftest.json').read_text())
    helper=ROOT/'ops/parallel_correctness.py'
    if not(acceptance.get('passed') is True and acceptance.get('native_calls')==acceptance.get('real_timing_samples')==0
           and acceptance.get('tool_sha256')==hashlib.sha256(helper.read_bytes()).hexdigest()):
        raise ValueError('Exact parallel helper synthetic acceptance missing')
    from ops.parallel_correctness import load_original, Snapshot
    frozen,_=load_original(CPU/'manifest.json',BUDGET,Snapshot())
    if len(frozen['plan'])!=3471:
        raise ValueError('Original full matrix scope differs')
    cmdlines = {pid: (Path('/proc') / str(pid) / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
                for pid in PIDS}
    if 'tools/check_optimization.py' not in cmdlines[PIDS[0]] or '--run-dir validation/cpu-full-repair-r3 ' not in cmdlines[PIDS[0]]:
        raise ValueError('Original CPU PID identity differs')
    if 'run-after-cpu-r3.sh' not in cmdlines[PIDS[1]] or 'run-after-matrix.sh' not in cmdlines[PIDS[2]]:
        raise ValueError('Waiting pipeline PID identity differs')
    cores = physical_cpus()[:args.core_budget]
    if len(cores) < 64:
        raise ValueError('Physical core inventory too small for original thread scope')
    WORK.mkdir()
    shutil.copyfile(Path(__file__), WORK / 'controller.py')
    signal_bits=int(next(line.split(':',1)[1] for line in (Path('/proc')/str(PIDS[0])/'status').read_text().splitlines()
                         if line.startswith('SigIgn:')),16)
    ignores_interrupt=bool(signal_bits & (1 << (signal.SIGINT-1)))
    write(WORK / 'handoff.json', dict(pids=cmdlines, cpu_signal='SIGTERM after stable SIGSTOP snapshot' if ignores_interrupt else 'SIGINT', waiting_signal='SIGSTOP',
          explanation='Inherited nohup may ignore SIGINT. External termination preserves original raw files; unfinished reservations are charged and marked failed.',
          core_budget=len(cores), physical_cpus=cores, formal_performance_started=False,
          real_timing_samples=0, controller_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    # Suspend both waiting controllers before the CPU exits. Resume only after a
    # verified complete aggregate is atomically published at their original path.
    os.kill(PIDS[2], signal.SIGSTOP)
    os.kill(PIDS[1], signal.SIGSTOP)
    if ignores_interrupt:
        os.kill(PIDS[0],signal.SIGSTOP)
        # Pause while taking the byte snapshot. A partially written record is
        # never accepted: let the original runner finish its append and retry.
        from tools.check_optimization import canonical,sha
        while True:
            time.sleep(0.1)
            content=(CPU/'cases.jsonl').read_bytes()
            try:
                if not content.endswith(b'\n'):
                    raise ValueError('Incomplete append')
                parsed=[json.loads(line) for line in content.splitlines()]
                if any(sha(canonical({k:v for k,v in r.items() if k!='record_sha256'}))!=r['record_sha256'] for r in parsed):
                    raise ValueError('Incomplete checksum')
                break
            except (ValueError,KeyError):
                os.kill(PIDS[0],signal.SIGCONT)
                time.sleep(0.2)
                os.kill(PIDS[0],signal.SIGSTOP)
        os.kill(PIDS[0],signal.SIGTERM)
        os.kill(PIDS[0],signal.SIGCONT)
    else:
        os.kill(PIDS[0], signal.SIGINT)
    print(json.dumps({'handoff_requested':True, 'waiting_pipelines_suspended':True}), flush=True)
    while alive(PIDS[0]):
        time.sleep(3)
    summary = json.loads((CPU / 'summary.json').read_text())
    if not summary['final'] and not ignores_interrupt:
        raise ValueError('Original runner did not write final interrupted checkpoint')
    CPU.rename(HISTORY)
    manifest = HISTORY / 'manifest.json'
    m = json.loads(manifest.read_text())
    rows = [json.loads(line) for line in (HISTORY / 'cases.jsonl').read_text().splitlines()]
    latest = {row['case_id']:row for row in rows}
    from tools.check_optimization import canonical, sha, case_id
    for row in rows:
        body = {key:value for key,value in row.items() if key != 'record_sha256'}
        if sha(canonical(body)) != row['record_sha256'] or row['status'] != 'passed':
            raise ValueError('Historical raw row invalid or failed')
    merge_serial=HISTORY
    if ignores_interrupt:
        from ops.parallel_correctness import arguments
        from tools.check_optimization import Runner
        from tools.signing_budget import SigningBudget
        ledger=SigningBudget(BUDGET)
        with ledger.connection() as db:
            unfinished=[row[0] for row in db.execute("SELECT receipt FROM reservations WHERE status='reserved'")]
        for receipt in unfinished:
            ledger.finish(receipt)
        merge_serial=WORK/'serial-snapshot'
        config=m['identity']['configuration']
        runner=Runner(arguments(config,run_dir=merge_serial))
        runner.close()
        shutil.copyfile(HISTORY/'cases.jsonl',merge_serial/'cases.jsonl')
        runner=Runner(arguments(config,run_dir=merge_serial,resume=True))
        try:
            summary=runner.checkpoint(error='External SIGTERM handoff: controller-generated snapshot; original unfinished raw summary retained separately',final=True)
        finally:
            runner.close()
        write(WORK/'termination.json',dict(original_summary_final=json.loads((HISTORY/'summary.json').read_text())['final'],
                original_files_sha256={name:hashlib.sha256((HISTORY/name).read_bytes()).hexdigest() for name in ('manifest.json','summary.json','cases.jsonl')},
                charged_aborted_receipts=unfinished,generated_snapshot=str(merge_serial),
                original_raw_evidence_preserved=True,native_calls=0,real_timing_samples=0))
    groups = collections.defaultdict(list)
    from ops.parallel_correctness import required_auxiliaries,auxiliary_plan
    allowed,_=auxiliary_plan(m['plan'])
    for case in m['plan']:
        row = latest.get(case['case_id'])
        complete = row is not None and row['passed']
        if complete:
            complete=all(latest.get(identifier,{}).get('passed') is True for identifier in required_auxiliaries(case,allowed))
        if not complete:
            groups[(case['pid'],case['backend'],case['threads'])].append(case['case_id'])
    assignments=[]
    for index,(key,ids) in enumerate(groups.items()):
        directory=WORK / f'worker-{index:02d}'
        selected=WORK / f'worker-{index:02d}.cases.json'
        write(selected, ids)
        assignments.append(dict(name=directory.name, directory=str(directory), cases_file=str(selected),
                                threads=key[2], pid=key[0], backend=key[1], case_ids=ids))
    # Start long low-thread groups early, then fill spare cores with 64-thread
    # groups. Every assigned core is a distinct physical core.
    assignments.sort(key=lambda item:(0 if item['pid'] in (3,103) and item['threads']<=8 else
                                      1 if item['pid'] in (3,103) else 2,
                                      item['threads'] if item['threads']<=8 else -item['threads'],
                                      -item['pid'], item['backend']))
    write(WORK / 'assignments.json', dict(assignments=assignments, pending_cases=sum(len(a['case_ids']) for a in assignments),
                                        completed_serial=summary['passed_planned'], full_plan=len(m['plan'])))
    print(json.dumps({'serial_preserved':str(HISTORY),'pending':sum(len(a['case_ids']) for a in assignments),
                      'groups':len(assignments),'physical_core_budget':len(cores)}),flush=True)
    pending=list(assignments)
    running=[]
    execution=[]
    env=dict(os.environ, OMP_DYNAMIC='FALSE', PYTHONUNBUFFERED='1')
    while pending or running:
        available=set(cores)
        for item in running:
            available.difference_update(item['cores'])
        for item in list(pending):
            if len(running)>=args.max_workers or item['threads']>len(available):
                continue
            assigned=sorted(available)[:item['threads']]
            logfile=WORK / (item['name']+'.log')
            stream=logfile.open('xb')
            command=[sys.executable,'ops/parallel_correctness.py','worker','--manifest',str(manifest),
                     '--run-dir',item['directory'],'--budget-db',str(BUDGET),
                     '--cases',item['cases_file'],'--cache-source',str(HISTORY)]
            def pin(cpuset=set(assigned)):
                os.sched_setaffinity(0, cpuset)
            process=subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, preexec_fn=pin)
            execution.append(dict(worker=item['name'],pid=process.pid,cores=assigned,threads=item['threads'],event='started'))
            running.append(dict(item=item,process=process,stream=stream,cores=assigned))
            pending.remove(item)
            available.difference_update(assigned)
            print(json.dumps({'started':item['name'],'pid':process.pid,'threads':item['threads'],'cores':assigned}),flush=True)
        for active in list(running):
            code=active['process'].poll()
            if code is None:
                continue
            active['stream'].close()
            running.remove(active)
            print(json.dumps({'finished':active['item']['name'],'returncode':code}),flush=True)
            execution.append(dict(worker=active['item']['name'],pid=active['process'].pid,event='finished',returncode=code))
            if code:
                raise ValueError('Worker failed; preserve all workers and suspended pipelines')
        time.sleep(2)
    write(WORK/'execution.json',dict(events=execution,all_workers_exited=True,all_returncodes_zero=True,
                                   core_budget=len(cores),formal_performance_started=False,real_timing_samples=0))
    if CPU.exists():
        raise ValueError('Canonical CPU path was recreated externally')
    command=['ops/parallel_correctness.py','merge','--manifest',str(manifest),'--budget-db',str(BUDGET),
             '--output',str(CPU),'--input-run',str(merge_serial)]
    for item in assignments:
        command.extend(['--input-run',item['directory']])
    run(command)
    result=json.loads((CPU/'summary.json').read_text())
    if not(result['passed'] and result['final'] and result['passed_planned']==result['planned_cases']==3471):
        raise ValueError('Merged full correctness scope incomplete')
    write(WORK/'published.json',dict(passed=True,canonical_path=str(CPU),summary_sha256=hashlib.sha256((CPU/'summary.json').read_bytes()).hexdigest(),
                                   formal_performance_started=False,real_timing_samples=0))
    os.kill(PIDS[1], signal.SIGCONT)
    os.kill(PIDS[2], signal.SIGCONT)
    print(json.dumps({'published':True,'CPU_full':'3471/3471','waiting_pipelines_resumed':True}),flush=True)

if __name__=='__main__':
    sys.path.insert(0,str(ROOT))
    main()
