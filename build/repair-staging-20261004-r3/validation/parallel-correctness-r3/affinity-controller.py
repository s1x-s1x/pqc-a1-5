"""Move remaining CPU workers to idle physical cores; preserve the adjustment."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,time
ROOT=Path('/home/guest-experiment/pqc-a1-5/build/repair-staging-20261004-r3')
WORK=ROOT/'validation/parallel-correctness-r3'
def sha(data):return hashlib.sha256(data).hexdigest()
def write(path,data):
    with path.open('x',encoding='utf-8') as f:f.write(json.dumps(data,indent=2)+'\n')
def sample():
    output={}
    for line in Path('/proc/stat').read_text().splitlines():
        name,*values=line.split()
        if name.startswith('cpu') and name[3:].isdigit():
            n=list(map(int,values));output[int(name[3:])]=(sum(n[:8]),n[3]+n[4])
    return output
os.chdir(ROOT)
if (WORK/'published.json').exists() or (WORK/'affinity-adjustment.json').exists():
    raise ValueError('Adjustment is no longer applicable or already exists')
assign=json.loads((WORK/'assignments.json').read_text())['assignments']
events=[]
for line in (ROOT/'validation/repair-pipeline/speed-controller.log').read_text().splitlines():
    try:events.append(json.loads(line))
    except ValueError:pass
starts={row['started']:row for row in events if 'started' in row}
finished={row['finished'] for row in events if 'finished' in row}
if set(starts)!={row['name'] for row in assign}:
    raise ValueError('Wait until every worker group has been launched')
live={name:row for name,row in starts.items() if name not in finished and (Path('/proc')/str(row['pid'])).exists()}
before=sample();time.sleep(1);after=sample()
idle={cpu:round(100*(after[cpu][1]-v[1])/max(1,after[cpu][0]-v[0]),1) for cpu,v in before.items()}
handoff_raw=(WORK/'handoff.json').read_bytes()
handoff=json.loads(handoff_raw)
permitted=handoff['physical_cpus']
occupied={cpu for row in live.values() for cpu in row['cores']}
free=sorted((cpu for cpu in permitted if cpu not in occupied),key=lambda cpu:(-idle[cpu],cpu))
requests=[]
for name,row in sorted(live.items()):
    group=next(item for item in assign if item['name']==name)
    if group['threads']>4:
        raise ValueError('Only final low-thread groups may be adjusted')
    targets=sorted(free[:group['threads']]);free=free[group['threads']:]
    if len(targets)!=group['threads'] or any(idle[cpu]<90 for cpu in targets):
        raise ValueError('Insufficient idle physical cores')
    requests.append((name,row,targets,group['threads']))
changes=[]
try:
    for name,row,targets,threads in requests:
        proc=Path('/proc')/str(row['pid'])
        if not proc.exists():continue
        command=(proc/'cmdline').read_bytes().replace(b'\0',b' ').decode()
        if 'ops/parallel_correctness.py worker ' not in command or '/'+name+' ' not in command:
            raise ValueError('Worker process identity changed')
        task_rows=[]
        for task in sorted((proc/'task').iterdir()):
            tid=int(task.name)
            old=sorted(os.sched_getaffinity(tid))
            os.sched_setaffinity(tid,set(targets))
            observed=sorted(os.sched_getaffinity(tid))
            if observed!=targets:raise ValueError('Affinity update was not applied')
            task_rows.append(dict(tid=tid,before=old,after=observed))
        changes.append(dict(worker=name,pid=row['pid'],threads=threads,assigned_initial_cores=row['cores'],
                            new_cores=targets,tasks=task_rows,command=command))
except BaseException:
    for change in changes:
        for task in change['tasks']:
            try:os.sched_setaffinity(task['tid'],set(task['before']))
            except ProcessLookupError:pass
    raise
controller_raw=Path(__file__).read_bytes()
with (WORK/'affinity-controller.py').open('xb') as f:f.write(controller_raw)
record=dict(schema='a15-correctness-affinity-adjustment-v1',status='applied',
            created_utc=datetime.now(timezone.utc).isoformat(),changes=changes,
            observed_idle_percent={str(cpu):idle[cpu] for cpu in permitted},
            scope='OS resource contention snapshot only; original cryptographic thread counts and inputs preserved',
            original_handoff_sha256=sha(handoff_raw),controller_sha256=sha(controller_raw),
            all_groups_launched=True,core_budget=handoff['core_budget'],native_calls=0,real_timing_samples=0,
            formal_performance_started=False)
write(WORK/'affinity-adjustment.json',record)
with (WORK/'handoff.before-affinity.json').open('xb') as f:f.write(handoff_raw)
handoff['external_affinity_adjustment']=dict(path=str(WORK/'affinity-adjustment.json'),
         sha256=sha((WORK/'affinity-adjustment.json').read_bytes()),original_handoff_sha256=sha(handoff_raw))
temporary=WORK/'handoff.affinity.tmp'
write(temporary,handoff)
temporary.replace(WORK/'handoff.json')
print(json.dumps(record))
