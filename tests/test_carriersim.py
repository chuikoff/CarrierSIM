"""Offline regression tests: temporary files and mocked device boundaries only."""
import asyncio
import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import carrier
import launch
from carriersim_version import VERSION


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def test_backup_roundtrip_preserves_files_directories_and_links(self):
        tree = {'bundle': ('d', b''), 'bundle/data': ('f', b'\x00\xff'),
                'alias': ('l', b'bundle'), 'empty': ('d', b'')}
        path = self.root / 'backup.zip'
        carrier.write_tree_zip(path, tree)
        self.assertEqual(carrier.read_tree_zip(path), tree)
        with self.assertRaises(FileExistsError):
            carrier.write_tree_zip(path, tree)

    def test_archive_rejects_path_traversal(self):
        for name in ('../outside', '/absolute', 'a/../b', 'a\\b', 'a//b', './x'):
            with self.subTest(name=name):
                path = self.root / 'bad.zip'
                with zipfile.ZipFile(path, 'w') as archive:
                    archive.writestr(name, b'bad')
                with self.assertRaises(RuntimeError):
                    carrier.read_tree_zip(path)

    def test_tree_rejects_invalid_parents_and_links(self):
        for tree in ({'missing/file': ('f', b'x')}, {'a': ('f', b'x'), 'a/b': ('f', b'y')},
                     {'link': ('l', b'a\x00b')}, {'x': ('unknown', b'')}):
            with self.subTest(tree=tree), self.assertRaises(RuntimeError):
                carrier.validate_tree(tree)

    def test_tree_limits(self):
        with patch.object(carrier, 'MAX_BYTES', 1), self.assertRaises(RuntimeError):
            carrier.validate_tree({'file': ('f', b'xx')})
        with patch.object(carrier, 'MAX_NODES', 0), self.assertRaises(RuntimeError):
            carrier.validate_tree({'empty': ('d', b'')})

    def test_hash_ignores_order_but_detects_content_and_type(self):
        tree = {'a': ('f', b'x'), 'b': ('f', b'y')}
        self.assertEqual(carrier.tree_hash(tree), carrier.tree_hash(dict(reversed(list(tree.items())))))
        for changed in ({'a': ('f', b'z'), 'b': ('f', b'y')}, {'a': ('l', b'x'), 'b': ('f', b'y')}):
            self.assertNotEqual(carrier.tree_hash(tree), carrier.tree_hash(changed))

    def test_json_is_utf8_and_replaces_existing_file(self):
        path = self.root / 'journal.json'
        carrier.save_json(path, {'message': 'Сохранено'})
        carrier.save_json(path, {'message': 'Обновлено'})
        self.assertEqual(carrier.read_json(path), {'message': 'Обновлено'})
        self.assertFalse(path.with_suffix('.json.tmp').exists())

    def test_bundled_assets_have_expected_digest_and_valid_tree(self):
        self.assertTrue(carrier.load_assets())

    def test_config_resolves_operator_then_default(self):
        path = self.root / 'bundle.yaml'
        path.write_text('\ufeff# comment\ndefault: Swisscom_ch\n"25001": "O2_Germany.bundle" # note\n', encoding='utf-8')
        config = carrier.load_bundle_config(path)
        self.assertEqual(carrier.bundle_for('25001', config), 'O2_Germany.bundle')
        self.assertEqual(carrier.bundle_for('25701', config), 'Swisscom_ch.bundle')
        self.assertEqual(carrier.load_bundle_config(self.root / 'missing'), {'default': carrier.BUNDLE})

    def test_config_rejects_duplicates_and_invalid_names(self):
        for value in ('default: ../bad', 'default: One\ndefault: Two', '250: One', 'invalid YAML'):
            with self.subTest(value=value):
                path = self.root / 'bundle.yaml'
                path.write_text(value, encoding='utf-8')
                with self.assertRaises(RuntimeError):
                    carrier.load_bundle_config(path)

    def test_pending_filters_by_phone_and_recovery_state(self):
        def journal(stage, **values):
            folder = self.root / '20260101-run' / stage
            folder.mkdir(parents=True)
            carrier.save_json(folder / 'journal.json', values)
            return folder
        wanted = journal('pending', udid_hash=carrier.digest(b'phone'), requires_recovery=True)
        journal('other', udid_hash=carrier.digest(b'other'), requires_recovery=True)
        journal('done', udid_hash=carrier.digest(b'phone'), requires_recovery=True, recovered_by='recovery')
        self.assertEqual(carrier.pending(self.root, 'phone'), [wanted])

    def test_operation_lock_can_be_reused_without_growing_file(self):
        for _ in range(3):
            with carrier.operation_lock(self.root):
                self.assertEqual((self.root / '.lock').stat().st_size, 1)

    def test_commcenter_report_requires_correct_slot_and_signature(self):
        path = self.root / 'syslog.txt'
        path.write_text(carrier.BUNDLE_BLOCK + '\nResolved path: /System/Other.bundle\n'
                        'Linking Path: /Carrier1Bundle.bundle\nVerification Result: Failed\n'
                        + carrier.BUNDLE_BLOCK + '\nResolved path: /System/O2_Germany.bundle\n'
                        'Linking Path: /Carrier2Bundle.bundle\nVerification Result: Success\n', encoding='utf-8')
        sims = [{'slot': 'kOne', 'plmn': '25001', 'bundle': 'Swisscom_ch.bundle'},
                {'slot': 'kTwo', 'plmn': '25002', 'bundle': 'O2_Germany.bundle'}]
        result = carrier.report_log(path, sims)
        self.assertFalse(result[0]['verified'])
        self.assertTrue(result[1]['verified'])
        self.assertEqual(result[1]['selected'], 'O2_Germany.bundle')


class SimsTest(unittest.TestCase):
    def setUp(self):
        self.rows = [dict(Slot='kOne', MCC='250', MNC='01', InternationalMobileSubscriberIdentity='250011234567890'),
                     dict(Slot='kTwo', MCC='250', MNC='02', InternationalMobileSubscriberIdentity='250029876543210')]

    def test_selected_sim_uses_its_operator_profile(self):
        result = carrier.select_sims(self.rows, {'25002': 'O2_Germany.bundle'}, ('kTwo',))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['bundle'], 'O2_Germany.bundle')
        self.assertEqual(result[0]['imsi'], self.rows[1]['InternationalMobileSubscriberIdentity'])

    def test_rejects_missing_selected_sim_duplicate_slot_and_invalid_imsi(self):
        cases = ([self.rows[0]], [self.rows[0], self.rows[0]],
                 [dict(self.rows[1], InternationalMobileSubscriberIdentity='123')],
                 [dict(self.rows[1], InternationalMobileSubscriberIdentity='257029876543210')])
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                carrier.select_sims(rows, slots=('kTwo',))

    def test_unselected_sim_without_imsi_does_not_block_selected_sim(self):
        self.rows[1].pop('InternationalMobileSubscriberIdentity')
        self.assertEqual(len(carrier.select_sims(self.rows, slots=('kOne',))), 1)

    def test_plan_changes_only_selected_imsi_and_preserves_original(self):
        original = {'25001': ('l', b'existing'), 'Info.plist': ('f', b'data')}
        sims = carrier.select_sims(self.rows, slots=('kTwo',))
        desired = carrier.make_plan(original, sims)
        self.assertEqual(desired['25001'], original['25001'])
        self.assertEqual(desired['Info.plist'], original['Info.plist'])
        self.assertNotIn(sims[0]['imsi'], original)
        self.assertEqual(desired[sims[0]['imsi']], carrier.bundle_link(carrier.BUNDLE))

    def test_plan_does_not_overwrite_a_regular_file(self):
        sims = carrier.select_sims(self.rows, slots=('kOne',))
        with self.assertRaises(RuntimeError):
            carrier.make_plan({sims[0]['imsi']: ('f', b'keep')}, sims)

    def test_restore_selected_sim_keeps_other_sim_and_non_imsi_nodes(self):
        a, b = [row['InternationalMobileSubscriberIdentity'] for row in self.rows]
        tree = {a: ('l', b'first'), b: ('l', b'second'), '25001': ('l', b'operator'),
                '123456789012345': ('f', b'keep')}
        restored = carrier.remove_imsi_links(tree, only={a})
        self.assertEqual(restored, {k: v for k, v in tree.items() if k != a})
        self.assertEqual(carrier.remove_imsi_links(tree), {k: v for k, v in tree.items() if k not in (a, b)})

    def test_masks_phone_and_identifiers_in_logs(self):
        masked = carrier.mask_phone('+7 (999) 123-45-67')
        self.assertIn('4567', masked)
        self.assertNotIn('999', masked)
        self.assertEqual(carrier.mask_phone(None), 'номер недоступен')
        self.assertNotIn('250011234567890', carrier.mask_log('IMSI 250011234567890'))

    def test_codec_answer_is_not_confused_with_offer(self):
        answer = 'm=audio 100 RTP/AVP 96 101\na=rtpmap:96 EVS/16000\na=rtpmap:101 telephone-event/8000'
        self.assertEqual(carrier.sip_answer_codec(answer), 'EVS/16000')
        self.assertIsNone(carrier.sip_answer_codec(answer.replace('96 101', '96 97 101') + '\na=rtpmap:97 AMR/8000'))


class BooksRestoreTest(unittest.IsolatedAsyncioTestCase):
    async def test_unchanged_books_file_is_not_opened_for_writing(self):
        afc = SimpleNamespace(get_file_contents=AsyncMock(return_value=b'original'),
                              set_file_contents=AsyncMock(), makedirs=AsyncMock())
        tree = {'Books.plist': ('f', b'original')}
        async def exists(_, path):
            if path == 'Books':
                return {'st_ifmt': 'S_IFDIR'}
            if path == 'Books/Books.plist':
                return {'st_ifmt': 'S_IFREG', 'st_size': 8}
            return None
        with patch.object(carrier, 'exists', exists), \
             patch.object(carrier, 'read_managed_books', AsyncMock(return_value=(True, tree))):
            self.assertEqual(await carrier.restore_books(afc, tree, True), [])
        afc.set_file_contents.assert_not_awaited()
        afc.makedirs.assert_not_awaited()

    async def test_missing_empty_managed_folder_is_recreated(self):
        state = {'Books': ('d', b'')}
        async def exists(_, path):
            return {'st_ifmt': 'S_IFDIR'} if path in state else None
        async def makedirs(path):
            state[path] = ('d', b'')
        async def read_managed(_):
            return True, {path.removeprefix('Books/'): value for path, value in state.items() if path != 'Books'}
        afc = SimpleNamespace(makedirs=AsyncMock(side_effect=makedirs))
        with patch.object(carrier, 'exists', exists), patch.object(carrier, 'read_managed_books', read_managed):
            self.assertEqual(await carrier.restore_books(afc, {'Managed': ('d', b'')}, True), [])
        afc.makedirs.assert_awaited_once_with('Books/Managed')
        self.assertIn('Books/Managed', state)

    async def test_unexpected_restored_contents_raise_instead_of_reporting_success(self):
        afc = SimpleNamespace()
        async def exists(_, path):
            return {'st_ifmt': 'S_IFDIR'} if path == 'Books' else None
        with patch.object(carrier, 'exists', exists), \
             patch.object(carrier, 'read_managed_books', AsyncMock(return_value=(True, {'Books.plist': ('f', b'unexpected')}))):
            with self.assertRaisesRegex(RuntimeError, 'Books'):
                await carrier.restore_books(afc, {}, True)


class RetryTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.args = SimpleNamespace(udid=None, wait_seconds=1, diagnose=False, watch_call=False,
                                    attempts=2, runs=self.root, status=False, recover=False)

    async def run_case(self, error, before, after):
        device = SimpleNamespace(close=AsyncMock())
        with patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'pending', side_effect=[before, after]), \
             patch.object(carrier, 'execute', AsyncMock(side_effect=error)), \
             patch.object(carrier, 'ready_device', AsyncMock(return_value=device)) as ready, \
             patch.object(carrier, 'recover_all', AsyncMock()) as recover, \
             patch.object(carrier, 'save_environment'), \
             patch.object(carrier, 'transient_error', return_value=False), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(type(error)):
                await carrier.execute_with_retry(self.args, {})
            return ready, recover, device

    async def test_status_failure_never_recovers_or_writes(self):
        self.args.status = True
        ready, recover, device = await self.run_case(RuntimeError('failed'), [], [self.root / 'stage'])
        ready.assert_not_awaited()
        recover.assert_not_awaited()
        device.close.assert_not_awaited()

    async def test_failure_does_not_recover_an_older_stage(self):
        old = self.root / 'old'
        ready, recover, _ = await self.run_case(RuntimeError('failed'), [old], [old])
        ready.assert_not_awaited()
        recover.assert_not_awaited()

    async def test_failure_recovers_only_new_stage_and_closes_device(self):
        old, new = self.root / 'old', self.root / 'new'
        _, recover, device = await self.run_case(RuntimeError('failed'), [old], [old, new])
        self.assertEqual(recover.await_args.args[1], [new])
        device.close.assert_awaited_once()

    async def test_read_only_diagnostics_bypasses_install_and_recovery(self):
        self.args.diagnose = True
        with patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')), \
             patch.object(carrier, 'diagnostics', AsyncMock(return_value=0)), \
             patch.object(carrier, 'execute', AsyncMock()) as execute, \
             patch.object(carrier, 'recover_all', AsyncMock()) as recover:
            self.assertEqual(await carrier.execute_with_retry(self.args, {}), 0)
            execute.assert_not_awaited()
            recover.assert_not_awaited()

    async def test_transient_failure_retries_same_phone(self):
        with patch.object(carrier, 'choose_device', AsyncMock(return_value='phone')) as choose, \
             patch.object(carrier, 'pending', return_value=[]), \
             patch.object(carrier, 'execute', AsyncMock(side_effect=[TimeoutError(), 0])) as execute, \
             patch.object(carrier, 'transient_error', return_value=True), \
             patch.object(carrier.asyncio, 'sleep', AsyncMock()), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(await carrier.execute_with_retry(self.args, {}), 0)
            self.assertEqual(execute.await_count, 2)
            choose.assert_awaited_once()
            self.assertEqual(self.args.udid, 'phone')


class VersionTest(unittest.TestCase):
    def test_cli_version_and_help_work_without_apple_services(self):
        for flag, expected in (('--version', f'CarrierSIM {VERSION}'), ('--help', '--recover')):
            result = subprocess.run([sys.executable, str(carrier.ROOT / 'carrier.py'), flag],
                                    capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(expected, result.stdout)

    def test_menu_displays_version(self):
        with patch('builtins.input', return_value='0'), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertIsNone(launch.menu())
        self.assertIn(f'CarrierSIM {VERSION}', output.getvalue())

    def test_log_environment_and_error_report_identify_version(self):
        with tempfile.TemporaryDirectory() as directory:
            run = pathlib.Path(directory)
            with patch.dict(carrier.DIAG, {}, clear=True):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    stdout, stderr = sys.stdout, sys.stderr
                    carrier.start_session_log(run)
                    log = sys.stdout.log
                    try:
                        print('console output')
                        print('error output', file=sys.stderr)
                    finally:
                        sys.stdout, sys.stderr = stdout, stderr
                        log.close()
                text = next(run.glob('*session.log')).read_text(encoding='utf-8')
                self.assertTrue(text.startswith(f'CarrierSIM {VERSION} · сборка '))
                self.assertIn('console output', text)
                self.assertIn('error output', text)
                carrier.save_environment(run)
                environment = carrier.read_json(run / 'environment.json')
                self.assertEqual(environment['CarrierSIM'], VERSION)
                self.assertEqual(len(environment['Сборка скрипта']), 12)
                carrier.DIAG['run'] = run
                with contextlib.redirect_stderr(io.StringIO()):
                    carrier.print_diagnostics(RuntimeError('test failure'))
                self.assertIn(f'CarrierSIM: {VERSION}', (run / 'diagnostics.txt').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
