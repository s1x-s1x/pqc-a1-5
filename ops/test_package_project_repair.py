"""Native-free synthetic package regression using temporary real Git repositories."""
from __future__ import annotations
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / 'ops/package_project_repair.py'
EVIDENCE = PROJECT / "build/repair-delivery-tools/package-regression"
EVIDENCE.mkdir(parents=True, exist_ok=True)
AUDIT = '''"""Synthetic read-only hash audit; no native code or timing."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
spec=json.loads((ROOT/'required.json').read_text(encoding='utf-8'))
evidence={}
for name,digest in spec['files'].items():
 assert sha(ROOT/name)==digest, name
 evidence[name]=digest
if spec.get('extra_path'):
 assert json.loads((ROOT/spec['extra_path']).read_text())['passed'] is True
evidence['required.json']=sha(ROOT/'required.json')
evidence['ops/audit_project_repair.py']=sha(Path(__file__))
if spec.get('closure_changes_after_unpack') and ROOT.name=='pqc-a1-5':
 evidence['extra-tracked.txt']=sha(ROOT/'extra-tracked.txt')
print(json.dumps(dict(schema='a15-project-repair-local-audit-v1',passed=True,
 evidence_sha256=evidence,native_calls=0,real_timing_samples=0,formal_performance_started=False,
 test_fixture_keys_sha256=spec.get('test_fixture_keys',{}),test_fixture_keys_test_only=True)))
'''

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

class PackageRepair(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='offline-repair-test-',dir=EVIDENCE)
        self.task=Path(self.temp.name)
        self.root=self.task/'project'
        self.root.mkdir()
        (self.root/'ops').mkdir()
        shutil.copyfile(SOURCE,self.root/'ops/package_project_repair.py')
        (self.root/'ops/audit_project_repair.py').write_text(AUDIT,encoding='utf-8')
        (self.root/'.gitignore').write_text('build/\nvalidation/optimization-external-evidence/*\n!validation/optimization-external-evidence/manifest.json\n',encoding='utf-8')
        (self.root/'README.md').write_text('Synthetic package source\n',encoding='utf-8')
        (self.root/'extra-tracked.txt').write_text('Additional tracked source\n',encoding='utf-8')
        self.stage_name='build/repair-staging-20261004-r3/validation/cpu-full-repair-r3/summary.json'
        self.stage=self.root/self.stage_name
        self.stage.parent.mkdir(parents=True)
        self.stage.write_text('{"passed":true,"synthetic":true}\n',encoding='utf-8')
        self.external_name='validation/optimization-external-evidence/usr/bin/fixture'
        self.external=self.root/self.external_name
        self.external.parent.mkdir(parents=True)
        self.external.write_bytes(b'SYNTHETIC EXTERNAL EVIDENCE')
        entry=dict(local_path=self.external_name,sha256=sha(self.external),size_bytes=self.external.stat().st_size)
        self.manifests=[self.root/'validation/optimization-external-evidence/manifest.json',
                        self.root/'validation/repair-external-evidence-r3-manifest.json']
        for p in self.manifests:
            p.write_text(json.dumps(dict(schema='a15-external-evidence-mirror-v1',files={'/usr/bin/fixture':entry})),encoding='utf-8')
        self.required=dict(files={'README.md':sha(self.root/'README.md'),self.stage_name:sha(self.stage)})
        self.write_required()
        self.out=self.task/'delivery.zip'
        spec=importlib.util.spec_from_file_location('synthetic_package_target',self.root/'ops/package_project_repair.py')
        self.module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        subprocess.run(['git','init','-q'],cwd=self.root,check=True,capture_output=True)
        self.commit()
    def tearDown(self):self.temp.cleanup()
    def write_required(self):
        (self.root/'required.json').write_text(json.dumps(self.required),encoding='utf-8')
    def commit(self):
        subprocess.run(['git','add','.'],cwd=self.root,check=True,capture_output=True)
        subprocess.run(['git','-c','user.name=Synthetic Test','-c','user.email=test@example.invalid','commit','-qm','Synthetic fixture'],cwd=self.root,check=True,capture_output=True)
    def call(self):
        with patch.object(sys,'argv',['package_project_repair.py','--output',str(self.out)]),contextlib.redirect_stdout(io.StringIO()):
            self.module.main()
    def no_products(self):
        self.assertFalse(self.out.exists())
        self.assertFalse(self.out.with_suffix('.manifest.json').exists())
        self.assertEqual(list(self.task.glob('.a15-offline-package-*')),[])
    def rewrite_entry(self,changes=None,original='/usr/bin/fixture'):
        data=json.loads(self.manifests[0].read_text())
        entry=data['files'].pop('/usr/bin/fixture')
        entry.update(changes or {})
        data['files'][original]=entry
        self.manifests[0].write_text(json.dumps(data),encoding='utf-8')
        self.commit()
    def test_includes_ignored_hash_closure_and_runs_unpacked_gate(self):
        self.call()
        tracked=subprocess.check_output(['git','ls-files','-z'],cwd=self.root).decode().split('\0')
        self.assertNotIn(self.stage_name,tracked)
        with zipfile.ZipFile(self.out) as archive:
            self.assertEqual(archive.read('pqc-a1-5/'+self.stage_name),self.stage.read_bytes())
            record=json.loads(archive.read('pqc-a1-5/OFFLINE-PACKAGE.json'))
            self.assertEqual(record['audited_evidence_sha256'][self.stage_name],sha(self.stage))
            self.assertIn('pqc-a1-5/'+self.external_name,archive.namelist())
        manifest=json.loads(self.out.with_suffix('.manifest.json').read_text())
        self.assertTrue(manifest['unpacked_audit_passed'])
        self.assertEqual(manifest['native_calls'],0)
        self.assertEqual(manifest['real_timing_samples'],0)
        self.assertEqual(manifest['archive_sha256'],sha(self.out))
    def test_unreported_audit_dependency_fails_clean_unpack_without_residue(self):
        p=self.root/'build/unreported/extra.json'
        p.parent.mkdir(parents=True)
        p.write_text('{"passed":true}',encoding='utf-8')
        self.required['extra_path']=p.relative_to(self.root).as_posix()
        self.write_required();self.commit()
        with self.assertRaises(subprocess.CalledProcessError):self.call()
        self.no_products()
    def test_unpacked_closure_change_rejected(self):
        self.required['closure_changes_after_unpack']=True
        self.write_required();self.commit()
        with self.assertRaisesRegex(ValueError,'closure differs'):self.call()
        self.no_products()
    def test_existing_sidecar_preserved(self):
        sidecar=self.out.with_suffix('.manifest.json')
        sidecar.write_text('PRESERVE THIS RECORD',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'new package and manifest'):self.call()
        self.assertEqual(sidecar.read_text(),'PRESERVE THIS RECORD')
        self.assertFalse(self.out.exists())
    def test_existing_archive_preserved(self):
        self.out.write_bytes(b'PREVIOUS ARCHIVE')
        with self.assertRaisesRegex(ValueError,'new package and manifest'):self.call()
        self.assertEqual(self.out.read_bytes(),b'PREVIOUS ARCHIVE')
    def test_windows_absolute_external_rejected(self):
        outside=self.task/'outside.bin';outside.write_bytes(b'OUTSIDE SYNTHETIC')
        self.rewrite_entry(dict(local_path=outside.as_posix(),sha256=sha(outside),size_bytes=outside.stat().st_size))
        with self.assertRaisesRegex(ValueError,'path identity'):self.call()
        self.no_products()
    def test_backslash_external_rejected(self):
        self.rewrite_entry(dict(local_path='..\\outside.bin'))
        with self.assertRaisesRegex(ValueError,'path identity'):self.call()
        self.no_products()
    def test_parent_original_rejected(self):
        self.rewrite_entry(dict(local_path='validation/optimization-external-evidence/usr/../outside'),original='/usr/../outside')
        with self.assertRaisesRegex(ValueError,'original path'):self.call()
        self.no_products()
    def test_missing_external_rejected(self):
        self.external.unlink()
        with self.assertRaisesRegex(ValueError,'member is missing'):self.call()
        self.no_products()
    def test_wrong_external_hash_rejected(self):
        self.rewrite_entry(dict(sha256='f'*64))
        with self.assertRaisesRegex(ValueError,'External bytes differ'):self.call()
        self.no_products()
    def test_wrong_external_size_rejected(self):
        self.rewrite_entry(dict(size_bytes=self.external.stat().st_size+1))
        with self.assertRaisesRegex(ValueError,'External bytes differ'):self.call()
        self.no_products()
    def test_stale_audited_hash_rejected(self):
        self.stage.write_text('{"passed":false}',encoding='utf-8')
        with self.assertRaises(subprocess.CalledProcessError):self.call()
        self.no_products()
    def test_tracked_private_fixture_rejected(self):
        p=self.root/'validation/handshake-test-key.json'
        p.write_text('{"synthetic":"NOT A REAL KEY"}',encoding='utf-8')
        self.commit()
        with self.assertRaisesRegex(ValueError,'explicit test-only binding'):self.call()
        self.no_products()
    def fixture_bundle(self):
        prefix = self.module.TEST_FIXTURE_ROOT
        entries, keys = [], {}
        for algorithm in self.module.TEST_FIXTURE_ALGORITHMS:
            directory = self.root / prefix / algorithm
            directory.mkdir(parents=True)
            files = {}
            for filename in self.module.PRIVATE_FIXTURE_NAMES:
                path = directory / filename
                path.write_text('Synthetic test-only fixture bytes: ' + algorithm + '/' + filename, encoding='utf-8')
                files[filename] = sha(path)
                keys[path.relative_to(self.root).as_posix()] = sha(path)
                self.required['files'][path.relative_to(self.root).as_posix()] = sha(path)
            fixture = directory / 'fixture.json'
            fixture.write_text(json.dumps(dict(schema='a15-alt-fixture-v1',test_only=True,
                alt_algorithm=algorithm,files_sha256=files)),encoding='utf-8')
            self.required['files'][fixture.relative_to(self.root).as_posix()] = sha(fixture)
            entries.append(dict(algorithm=algorithm,fixture_sha256=sha(fixture)))
        bundle = self.root / prefix / 'MANIFEST.json'
        bundle.write_text(json.dumps(dict(schema='a15-alt-fixtures-v1',test_only=True,fixtures=entries)),encoding='utf-8')
        self.required['files'][bundle.relative_to(self.root).as_posix()] = sha(bundle)
        self.required['test_fixture_keys'] = keys
        self.write_required();self.commit()
        return bundle
    def test_authorized_hash_bound_test_fixture_keys_are_included(self):
        self.fixture_bundle()
        self.call()
        with zipfile.ZipFile(self.out) as archive:
            record=json.loads(archive.read('pqc-a1-5/OFFLINE-PACKAGE.json'))
            self.assertTrue(record['test_only_fixture_material'])
            self.assertTrue(record['test_fixture_material']['test_only'])
            self.assertEqual(len(record['test_fixture_keys_sha256']),12)
            for name,digest in self.required['test_fixture_keys'].items():
                self.assertEqual(hashlib.sha256(archive.read('pqc-a1-5/'+name)).hexdigest(),digest)
    def test_fixture_bundle_without_test_only_rejected(self):
        bundle=self.fixture_bundle()
        data=json.loads(bundle.read_text());data['test_only']=False
        bundle.write_text(json.dumps(data),encoding='utf-8')
        self.required['files'][bundle.relative_to(self.root).as_posix()]=sha(bundle)
        self.write_required();self.commit()
        with self.assertRaisesRegex(ValueError,'not marked test_only'):self.call()
        self.no_products()
    def test_test_key_map_outside_declared_bundle_rejected(self):
        self.fixture_bundle()
        key,digest=next(iter(self.required['test_fixture_keys'].items()))
        del self.required['test_fixture_keys'][key]
        self.required['test_fixture_keys']['validation/handshake-test-key.json']=digest
        self.write_required();self.commit()
        with self.assertRaisesRegex(ValueError,'leave the declared'):self.call()
        self.no_products()
    def test_portable_member_names(self):
        for bad in ['', '.', '..', '../x', '/x', 'C:/x', '..\\x', '//host/x', 'a//b', 'a/./b', 'a/', 'a.','a ', 'NUL.txt']:
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):self.module.member_name(bad)
        self.assertEqual(self.module.member_name('docs/report.md'),'docs/report.md')
    def test_live_ignored_evidence_mutation_rejected(self):
        original=self.module.extract_and_audit
        def mutate(*args):
            original(*args)
            self.stage.write_text('{"changed":true}',encoding='utf-8')
        with patch.object(self.module,'extract_and_audit',mutate):
            with self.assertRaisesRegex(ValueError,'changed while packaging'):self.call()
        self.no_products()
    def test_publication_sidecar_race_preserves_prior_record_and_cleans_archive(self):
        original=self.module.publish_exclusive
        def collision(source,destination):
            if destination==self.out.with_suffix('.manifest.json'):
                destination.write_text('RACING RECORD',encoding='utf-8')
            original(source,destination)
        with patch.object(self.module,'publish_exclusive',collision):
            with self.assertRaises(FileExistsError):self.call()
        self.assertFalse(self.out.exists())
        self.assertEqual(self.out.with_suffix('.manifest.json').read_text(),'RACING RECORD')
        self.assertEqual(list(self.task.glob('.a15-offline-package-*')),[])

if __name__=='__main__':
    stream=io.StringIO()
    result=unittest.TextTestRunner(stream=stream,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PackageRepair))
    record=dict(schema='a15-offline-package-repair-synthetic-v1',passed=result.wasSuccessful(),
        tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
        source_sha256=sha(SOURCE),native_calls=0,real_timing_samples=0,
        actual_project_acceptance=False,notes='Real temporary Git repositories and a synthetic read-only hash audit. No real package is published.')
    (EVIDENCE/'offline-package-repair-tests.log').write_text(stream.getvalue(),encoding='utf-8')
    (EVIDENCE/'offline-package-repair-tests.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(stream.getvalue());print(json.dumps(record))
    raise SystemExit(not result.wasSuccessful())
