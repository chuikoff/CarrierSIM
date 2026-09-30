#!/usr/bin/env python3
"""Vodafone HU для всех обнаруженных SIM по полному IMSI."""
from __future__ import annotations
import argparse
import asyncio
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import struct
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parent

PARENT = '/var/mobile/Library/Carrier Bundles'
TARGET = PARENT + '/iPhone'
PAYLOAD_PATH = 'q0/q1/q2/q3/q4/payload'
BUNDLE = 'Vodafone_hu.bundle'
MAX_BYTES = 64 * 1024 * 1024
MAX_NODES = 4000
BOOK_FILES = ('Books/Books.plist', 'Books/Sync/Books.plist', 'Books/Sync/Upload.plist',
              'Books/Sync/Database/OutstandingAssets_4.sqlite',
              'Books/Sync/Database/OutstandingAssets_4.sqlite-shm',
              'Books/Sync/Database/OutstandingAssets_4.sqlite-wal')
BOOK_DIRS = ('Books', 'Books/Managed', 'Books/Sync', 'Books/Sync/Database')
AFC_PERM_DENIED = 10  # pymobiledevice3 AfcError.PERM_DENIED
# usbmux transport: 'USB' or 'Network' (Wi-Fi sync, set by --wifi).
CONNECTION = 'USB'
# Over the cable usbmuxd drops the socket as soon as the phone is gone; over Wi-Fi a sleeping
# phone can leave AFC waiting for hours. A Wi-Fi transfer takes about 25 s, host_session caps
# AirTraffic at 170 s. Recovery starts over a fresh connection and restores Books from books.zip.
NETWORK_TRANSFER_SECONDS = 300
NETWORK_BOOKS_SECONDS = 90


def network_timeout(seconds):
    return asyncio.timeout(seconds) if CONNECTION == 'Network' else contextlib.nullcontext()



def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def recover_hint():
    # The launcher menu runs this script with CARRIERSIM_MENU=1; its users never type flags.
    if os.environ.get('CARRIERSIM_MENU'):
        return 'выберите в меню пункт 5 «Восстановить после сбоя»'
    return 'запустите скрипт с флагом --recover'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def save_json(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)

def safe_name(name):
    require(bool(name) and not name.startswith('/') and '\\' not in name and
            all(p not in ('', '.', '..') for p in name.split('/')), 'Unsafe tree path: ' + name)
    return name


def validate_tree(tree):
    require(len(tree) <= MAX_NODES, 'Too many tree nodes')
    require(sum(len(v[1]) for v in tree.values()) <= MAX_BYTES, 'Tree too large')
    for name, (kind, data) in tree.items():
        safe_name(name)
        require(kind in ('d', 'f', 'l'), 'Unknown node type')
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.':
                require(tree.get(str(parent), (None,))[0] == 'd', 'Missing or non-directory parent')
        if kind == 'l':
            require(b'\x00' not in data and len(data) <= 4096, 'Invalid symlink')

def tree_hash(tree):
    return digest(json.dumps({n: [k, digest(b)] for n, (k, b) in sorted(tree.items())},
                             sort_keys=True).encode())

def zi(name, kind, streaming=False):
    mode = {'f': stat.S_IFREG | 0o644, 'd': stat.S_IFDIR | 0o755,
            'l': stat.S_IFLNK | 0o777}[kind]
    z = zipfile.ZipInfo(name + ('/' if kind == 'd' and not name.endswith('/') else ''),
                        (2026, 9, 24, 0, 0, 0))
    z.create_system = 3
    z.external_attr = mode << 16
    if streaming:
        z.extra = struct.pack('<HHH', 0x5A53, 2, mode)
    return z

def write_tree_zip(path, tree):
    validate_tree(tree)
    with zipfile.ZipFile(path, 'x') as z:
        for name, (kind, data) in sorted(tree.items()):
            z.writestr(zi(name, kind), data)

def read_tree_zip(path):
    tree = {}
    with zipfile.ZipFile(path) as z:
        require(len(z.infolist()) <= MAX_NODES and sum(i.file_size for i in z.infolist()) <= MAX_BYTES,
                'Archive too large')
        for i in z.infolist():
            name = safe_name(i.filename.rstrip('/'))
            require(name not in tree, 'Duplicate archive entry')
            mode = stat.S_IFMT(i.external_attr >> 16)
            require(mode in (0, stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK), 'Unsupported archive type')
            tree[name] = ('d' if i.is_dir() else 'l' if mode == stat.S_IFLNK else 'f', z.read(i))
    validate_tree(tree)
    return tree

def bundle_info(tree, name=BUNDLE):
    prefix = name + '/'
    def pl(file):
        value = tree.get(prefix + file)
        require(value is not None and value[0] == 'f', 'Missing ' + prefix + file)
        return plistlib.loads(value[1])
    info, carrier = pl('Info.plist'), pl('carrier.plist')
    require(any(n.startswith(prefix + 'signatures/') and k == 'f' for n, (k, _) in tree.items()),
            'No signature files (presence is not cryptographic verification)')
    return info, carrier

def staging_archive(payload=None):
    # Six staging levels keep system links inside the ZIP while unpacking.
    # After placement the same six '..' components resolve from /private/var/mobile/... to /.
    tree = {'META-INF': ('d', b''), 'META-INF/com.apple.ZipMetadata.plist':
            ('f', plistlib.dumps({'Version': 2}, fmt=plistlib.FMT_BINARY)),
            'p0': ('d', b''), 'p0/p1': ('d', b''), 'p0/p1/p2': ('d', b''),
            'p0/p1/p2/link': ('l', ('../../../' + PARENT[1:]).encode())}
    def directories(path):
        cursor = ''
        for part in path.split('/'):
            cursor += ('/' if cursor else '') + part
            tree[cursor] = ('d', b'')
    directories(PARENT[1:])
    if payload is not None:
        directories(PAYLOAD_PATH)
        system_names = set(TARGET_BUNDLES)
        for kind, data in payload.values():
            if kind == 'l' and data.startswith(SYSTEM_PREFIX.encode()):
                name = data.decode().removeprefix(SYSTEM_PREFIX)
                require(re.fullmatch(r'[A-Za-z0-9_]+\.bundle', name), 'Неожиданная системная ссылка')
                system_names.add(name)
        for name in system_names:
            directories('System/Library/Carrier Bundles/iPhone/'+name)
        tree.update({PAYLOAD_PATH+'/'+n:v for n,v in payload.items()})
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', allowZip64=False) as z:
        for name, (kind, data) in sorted(tree.items()):
            z.writestr(zi(name, kind, streaming=True), data)
    return b.getvalue()

async def exists(afc, path):
    from pymobiledevice3.exceptions import AfcFileNotFoundError
    try:
        return await afc.stat(path)
    except AfcFileNotFoundError:
        return None

async def remote_tree(afc, root):
    tree = {}
    total = 0
    async def visit(path, name='', depth=0):
        nonlocal total
        require(depth < 32, 'Слишком глубокая вложенность папок: ' + path)
        require(len(tree) < MAX_NODES, f'Больше {MAX_NODES} объектов в {root}: лимит скрипта')
        before = await afc.stat(path)
        kind = before['st_ifmt']
        if kind == 'S_IFDIR':
            if name:
                tree[name] = ('d', b'')
            children = sorted(await afc.listdir(path))
            for child in children:
                require(child not in ('', '.', '..') and '/' not in child, 'Invalid remote name')
                await visit(path + '/' + child, name + '/' + child if name else child, depth + 1)
            require(children == sorted(await afc.listdir(path)), 'Remote directory changed')
        elif kind == 'S_IFLNK':
            require(name, 'Root is a symlink')
            tree[name] = ('l', before['LinkTarget'].encode())
        elif kind == 'S_IFREG':
            require(name, 'Root is a file')
            require(before['st_size'] <= MAX_BYTES, f'Файл больше {MAX_BYTES >> 20} МБ: {path} ({before["st_size"] >> 20} МБ)')
            data = await afc.get_file_contents(path)
            require(len(data) == before['st_size'], 'Файл изменился во время чтения: ' + path)
            total += len(data)
            require(total <= MAX_BYTES, f'В {root} больше {MAX_BYTES >> 20} МБ данных (прочитано {total >> 20} МБ, '
                                        f'последний файл {path}, {len(data) >> 10} КБ): лимит скрипта')
            tree[name] = ('f', data)
        else:
            raise RuntimeError('Unsupported remote node: ' + path)
        after = await afc.stat(path)
        require(before == after, 'Remote file changed during read: ' + path)
    require((await afc.stat(root))['st_ifmt'] == 'S_IFDIR', 'Carrier root is not a directory')
    await visit(root)
    validate_tree(tree)
    return tree

BOOK_LOCKS = ('Managed/.Managed.plist.lock', 'Sync/.bookSync.lock')


async def read_managed_books(afc):
    # Only what this script touches in Books: AirTraffic's sync files and folders. The user's
    # library (hundreds of MB of books, Purchases, MetadataStore) is never read or copied.
    node = await exists(afc, 'Books')
    if node is None:
        return False, {}
    require(node['st_ifmt'] == 'S_IFDIR', 'Books is not a directory')
    tree = {}
    for path in BOOK_DIRS[1:]:
        found = await exists(afc, path)
        if found is not None:
            require(found['st_ifmt'] == 'S_IFDIR', 'Unexpected Books directory: ' + path)
            tree[path.removeprefix('Books/')] = ('d', b'')
    for path in list(BOOK_FILES) + ['Books/' + rel for rel in BOOK_LOCKS]:
        found = await exists(afc, path)
        if found is None:
            continue
        require(found['st_ifmt'] == 'S_IFREG', 'Unexpected Books sync artifact: ' + path)
        require(found['st_size'] <= MAX_BYTES, f'Файл больше {MAX_BYTES >> 20} МБ: {path}')
        data = await afc.get_file_contents(path)
        require(len(data) == found['st_size'], 'Файл изменился во время чтения: ' + path)
        tree[path.removeprefix('Books/')] = ('f', data)
    validate_tree(tree)
    return True, tree


async def books_snapshot(afc, run):
    # Books may write its sync files in the background: take two identical reads in a row.
    state = await read_managed_books(afc)
    for _ in range(10):
        await asyncio.sleep(1)
        again = await read_managed_books(afc)
        if again == state:
            break
        state = again
    else:
        raise RuntimeError('Служебные файлы Books постоянно меняются: закройте приложение «Книги» '
                           'на iPhone, дождитесь окончания загрузки книг и повторите.')
    existed, tree = state
    write_tree_zip(run / 'books.zip', tree)
    top = sorted(await afc.listdir('Books')) if existed else []
    save_json(run / 'books.json', {'existed': existed, 'hash': tree_hash(tree), 'top': top})
    return tree, existed


# Book lists where AirTraffic registers synced items. A run whose Books cleanup failed (older
# versions) leaves our fake items there; atc then treats the catalog item as already installed
# (installOnly) and omits it from the manifest, so every later run fails. These entries are ours.
BOOK_LISTS = ('Books/Books.plist', 'Books/Backup-Books.plist', 'Books/Sync/Books.plist')


def our_trace(value):
    # This script's asset IDs: unique airlift-* staging names or the catalog path they resolve to.
    if isinstance(value, bytes):
        return b'airlift-' in value or b'Carrier Bundles/iPhone' in value
    value = str(value or '')
    return 'airlift-' in value or value.endswith('Carrier Bundles/iPhone')


def ours(item):
    return isinstance(item, dict) and our_trace(item.get('Persistent ID'))


async def purge_stale_books(afc, run):
    from pymobiledevice3.exceptions import AfcException
    removed = {}
    for path in BOOK_LISTS:
        node = await exists(afc, path)
        if node is None or node['st_ifmt'] != 'S_IFREG':
            continue
        raw = await afc.get_file_contents(path)
        try:
            data = plistlib.loads(raw)
        except Exception:
            continue
        items = data.get('Books') if isinstance(data, dict) else None
        if not isinstance(items, list) or not any(ours(i) for i in items):
            continue
        (run / 'books-stale').mkdir(exist_ok=True)
        (run / 'books-stale' / path.replace('/', '_')).write_bytes(raw)
        data['Books'] = [i for i in items if not ours(i)]
        fmt = plistlib.FMT_BINARY if raw.startswith(b'bplist') else plistlib.FMT_XML
        clean = plistlib.dumps(data, fmt=fmt)
        try:
            await afc.set_file_contents(path, clean)
        except AfcException as error:
            # Some Books files are not writable over AFC (status 10, permission denied).
            # An open that failed changed nothing; record it and clean the rest.
            # Any other AFC failure (no space, lost connection) must not pass as "denied".
            if error.status != AFC_PERM_DENIED:
                raise
            removed[path] = 'запись запрещена: ' + str(error)
            continue
        require(await afc.get_file_contents(path) == clean, 'Не удалось очистить ' + path)
        removed[path] = len(items) - len(data['Books'])
    return removed



# ---- Leftovers of earlier runs, removed from the phone itself (no need to keep old runs folders).
LEFTOVER = re.compile(r'airlift-(src|link|saved)-[0-9a-f]{20}')
OUTSTANDING_DB = 'Books/Sync/Database/OutstandingAssets_4.sqlite'


async def remove_tree(afc, path):
    # AFC stat does not follow symlinks: a link is removed itself, never what it points to.
    node = await afc.stat(path)
    if node['st_ifmt'] == 'S_IFDIR':
        for child in await afc.listdir(path):
            require(child not in ('', '.', '..') and '/' not in child, 'Invalid remote name')
            await remove_tree(afc, path + '/' + child)
    await afc.rm_single(path)


def read_outstanding(files):
    # OutstandingAssets_4.sqlite with its WAL, as {suffix: bytes}: rows (persistent ID, completed path).
    # Raises sqlite3.Error when the database cannot be read.
    import sqlite3
    with tempfile.TemporaryDirectory() as d:
        for suffix, data in files.items(): (Path(d)/('db.sqlite' + suffix)).write_bytes(data)
        db = sqlite3.connect(Path(d)/'db.sqlite')
        try: return db.execute('select ZPERSISTENTID, ZDOWNLOADCOMPLETEPATH from ZBCOUTSTANDINGASSET').fetchall()
        finally: db.close()


async def purge_outstanding(afc, run):
    # Books' queue of unfinished sync downloads. Rows of an interrupted run make atc skip the
    # catalog. Only when every row is ours is the database removed (Books recreates it empty).
    import sqlite3
    files = {}
    for suffix in ('', '-wal', '-shm'):
        if await exists(afc, OUTSTANDING_DB + suffix):
            files[suffix] = await afc.get_file_contents(OUTSTANDING_DB + suffix)
    if '' not in files:
        return None
    try:
        rows = [r[0] or '' for r in read_outstanding(files)]
    except sqlite3.Error as error:
        return 'не прочитана: ' + str(error)
    mine = [x for x in rows if our_trace(x)]
    if not mine:
        return 0
    if len(mine) != len(rows):
        return f'оставлена: наших {len(mine)} из {len(rows)}'
    (run / 'books-stale').mkdir(exist_ok=True)
    for suffix, data in files.items():
        (run / 'books-stale' / ('OutstandingAssets_4.sqlite' + suffix)).write_bytes(data)
    for suffix in ('-wal', '-shm', ''):
        if suffix in files: await afc.rm_single(OUTSTANDING_DB + suffix)
    return len(mine)


async def clean_phone(device, run):
    from pymobiledevice3.services.afc import AfcService
    report = {}
    async with AfcService(device) as afc:
        for name in sorted(n for n in await afc.listdir('/') if LEFTOVER.fullmatch(n)):
            node = await afc.stat(name)
            if name.startswith('airlift-saved-') and node['st_ifmt'] == 'S_IFDIR':
                # An exported carrier catalog, possibly the only copy of it (a run from another
                # copy of the folder leaves no journal here). Removed only after a local copy
                # is written and read back identical; otherwise it stays on the phone.
                try:
                    tree = await remote_tree(afc, name)
                    (run / 'media-leftovers').mkdir(exist_ok=True)
                    copy = run / 'media-leftovers' / (name + '.zip')
                    write_tree_zip(copy, tree)
                    require(read_tree_zip(copy) == tree, 'копия не совпала')
                except Exception as error:
                    report[name] = 'не удалён: локальная копия не сохранена: ' + str(error)
                    continue
            try:
                await remove_tree(afc, name)
                report[name] = 'удалён'
            except Exception as error:
                report[name] = 'не удалён: ' + str(error)
        lists = await purge_stale_books(afc, run)
        if lists: report['списки Books'] = lists
        outstanding = await purge_outstanding(afc, run)
        if outstanding: report['загрузки Books'] = outstanding
    save_json(run / 'cleanup.json', report)
    DIAG['cleanup'] = report
    return report


async def books_change(afc, path, action, denied):
    # Some Books files are not writable over AFC (status 10) although iOS itself rewrites them.
    # Such a file is left as iOS made it, unless it still holds this script's staging entries.
    from pymobiledevice3.exceptions import AfcException
    try:
        await action
    except AfcException as error:
        if error.status != AFC_PERM_DENIED:
            raise
        data = await afc.get_file_contents(path) if await exists(afc, path) else b''
        require(not our_trace(data),
                'iPhone запрещает изменить ' + path + ', а в нём остались записи скрипта. '
                'Копии сохранены в папке runs — не удаляйте её. Сообщите автору текст этой ошибки.')
        denied.add(path.removeprefix('Books/'))


async def restore_books(afc, tree, existed, top=None):
    denied = set()
    for path in BOOK_FILES:
        rel = path.removeprefix('Books/')
        current = await exists(afc, path)
        require(current is None or current['st_ifmt'] == 'S_IFREG', 'Unexpected Books artifact; keep backup')
        if rel in tree:
            # An unchanged file is not opened for writing at all.
            if current is not None and await afc.get_file_contents(path) == tree[rel][1]:
                continue
            await afc.makedirs(str(PurePosixPath(path).parent))
            await books_change(afc, path, afc.set_file_contents(path, tree[rel][1]), denied)
            if rel not in denied:
                require(await afc.get_file_contents(path) == tree[rel][1], 'Books restore mismatch')
        elif current:
            await books_change(afc, path, afc.rm_single(path), denied)
    # AirTraffic created these empty lock files during the first physical test.
    # Never delete a pre-existing lock or one with unexpected contents/type.
    for rel in BOOK_LOCKS:
        if rel not in tree:
            path = 'Books/' + rel
            node = await exists(afc, path)
            if node is not None:
                require(node['st_ifmt'] == 'S_IFREG' and node['st_size'] == 0,
                        'Unexpected generated Books lock; retain backup')
                await books_change(afc, path, afc.rm_single(path), denied)
    for path in BOOK_DIRS[1:]:
        # A sync folder that existed before (possibly empty) but was removed during the session.
        if path.removeprefix('Books/') in tree and await exists(afc, path) is None:
            await afc.makedirs(path)
    for path in reversed(BOOK_DIRS):
        was_present = existed if path == 'Books' else path.removeprefix('Books/') in tree
        if not was_present and await exists(afc, path) and not await afc.listdir(path):
            await afc.rm_single(path)
    # Only files and folders this function restores must match the backup. The rest of Books
    # (Purchases, MetadataStore, the user's books) may be rewritten by iOS during the session;
    # it cannot be put back from here, so a top-level difference is reported, not a failure.
    _, after = await read_managed_books(afc)
    managed = {p.removeprefix('Books/') for p in BOOK_FILES + BOOK_DIRS[1:]} | set(BOOK_LOCKS)
    tree = {n: v for n, v in tree.items() if n in managed}  # backups from older versions hold all of Books
    # Files iOS does not let us write stay as iOS left them: reported, not a failure.
    tree = {n: v for n, v in tree.items() if n not in denied}
    after = {n: v for n, v in after.items() if n not in denied}
    diff = ([f'+{n}' for n in sorted(after.keys() - tree.keys())] +
            [f'-{n}' for n in sorted(tree.keys() - after.keys())] +
            [f'~{n}' for n in sorted(tree.keys() & after.keys()) if tree[n] != after[n]])
    require(not diff, 'Не удалось вернуть служебные файлы Books на iPhone в исходное состояние. '
            'Копии сохранены в папке runs — не удаляйте её. Сообщите автору текст этой ошибки. '
            'Отличаются (+ появилось, - пропало, ~ изменилось): ' + ', '.join(diff[:10]))
    kept = sorted('!' + n + ' (запись запрещена iOS)' for n in denied)
    if top is None:
        return kept
    now = set(await afc.listdir('Books')) if await exists(afc, 'Books') else set()
    return kept + sorted('+' + n for n in now - set(top)) + sorted('-' + n for n in set(top) - now)


# Device-side view of an AirTraffic session: atc decides which assets enter the manifest.
DEVICE_LOG_KEYS = ('atc', 'airtraffic', 'book', 'sandbox', 'deny', 'airlift', 'carrier bundles',
                   'itunes', 'medialibrary', 'mobile.lockdown')


@contextlib.asynccontextmanager
async def syslog_capture(device, path, keep, status=None, linger=1):
    # Diagnostics only: a slow, broken or overflowing syslog never fails the operation.
    # Its error goes into the log file and, when given, status['log_error'].
    from pymobiledevice3.services.syslog import SyslogService
    ready = asyncio.Event()
    async def watch():
        try:
            async with SyslogService(device) as log:
                ready.set()
                size = 0
                with path.open('w', encoding='utf-8') as f:
                    async for row in log.watch():
                        line = row.decode(errors='replace') if isinstance(row, bytes) else row
                        if keep(line):
                            size += len(line)
                            require(size <= 16 * 1024 * 1024, 'Log limit reached')
                            f.write(line + '\n'); f.flush()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if status is not None:
                status['log_error'] = type(error).__name__ + ': ' + str(error)
            with contextlib.suppress(Exception):
                with path.open('a', encoding='utf-8') as f: f.write('LOG ERROR: ' + repr(error) + '\n')
        finally:
            ready.set()
    task = asyncio.create_task(watch())
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(ready.wait(), 10)
    try:
        yield
    finally:
        await asyncio.sleep(linger)  # let the phone flush the last lines
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def device_log(device, path):
    return syslog_capture(device, path, lambda line: any(k in line.lower() for k in DEVICE_LOG_KEYS))


async def transfer(device, run, payload=None, expected=None, recovery=False):
    from pymobiledevice3.services.afc import AfcService
    run.mkdir(parents=True, exist_ok=False)
    token = os.urandom(10).hex()
    source, link, exported = ('airlift-' + t + '-' + token for t in ('src', 'link', 'saved'))
    final_source = source + '/' + PAYLOAD_PATH if payload is not None else exported
    # Books keeps finished items in Sync/Database/OutstandingAssets_4.sqlite keyed by this ID.
    # A fixed '../../../Library/...' ID matches rows left by an interrupted run and atc then
    # skips the catalog (installOnly). Going through this run's staging folder resolves to the
    # same path (Media/<source>/../../Library = /var/mobile/Library) but is unique per run.
    assets = [(f'../../{source}/p0/p1/p2/link', link),
              (f'../../{source}/../../' + TARGET.removeprefix('/var/mobile/'), exported),
              ('../../' + final_source, link + '/iPhone')]
    journal = {'schema': 1, 'udid_hash': digest(device.udid.encode()), 'target': TARGET,
               'source': source, 'link': link, 'exported': exported,
               'complete': False, 'phase': 'created', 'payload_hash': tree_hash(payload) if payload is not None else None}
    def phase(name, **values):
        journal.update(phase=name, **values)
        save_json(run / 'journal.json', journal)
    phase('created')
    snapshot = None
    async with network_timeout(NETWORK_TRANSFER_SECONDS), AfcService(device) as afc:
        for path in (source, link, exported):
            require(await exists(afc, path) is None, 'Staging path collision')
        leftovers = sorted(n for n in await afc.listdir('/') if n.startswith('airlift-'))
        if leftovers:
            journal['media_leftovers'] = leftovers; save_json(run / 'journal.json', journal)
        stale = await purge_stale_books(afc, run)
        if stale:
            journal['stale_books_removed'] = stale; save_json(run / 'journal.json', journal)
        books, books_existed = await books_snapshot(afc, run)
        books_top = read_json(run / 'books.json')['top']
        mutated = False
        try:
            raw = staging_archive(payload)
            (run / 'staging.zip').write_bytes(raw)
            if payload is not None:
                write_tree_zip(run / 'desired.zip', payload)
            phase('staging', requires_recovery=True)
            mutated = True
            service = await device.start_lockdown_service('com.apple.streaming_zip_conduit')
            try:
                await service.send_plist({'MediaSubdir': source}, fmt=plistlib.FMT_BINARY)
                await service.sendall(raw)
                reply = await asyncio.wait_for(service.recv_plist(), 30)
                require(reply.get('Status') == 'DataComplete', 'Streaming ZIP was rejected')
            finally:
                await service.close()
            node = await afc.stat(source + '/p0/p1/p2/link')
            require(node['st_ifmt'] == 'S_IFLNK' and node.get('LinkTarget') == '../../../' + PARENT[1:],
                    'Staged link mismatch')
            if payload is not None:
                require(await remote_tree(afc, source + '/' + PAYLOAD_PATH) == payload, 'Staged carrier tree mismatch')
            await afc.makedirs('Books/Sync')
            metadata = plistlib.dumps({'Books': [{'Persistent ID': a, 'Item ID': str(i), 'DSID': '1'}
                                      for i, (a, _) in enumerate(assets, 1)]}, fmt=plistlib.FMT_BINARY)
            await afc.set_file_contents('Books/Sync/Books.plist', metadata)
            require(await afc.get_file_contents('Books/Sync/Books.plist') == metadata, 'Books staging mismatch')
            async def pause():
                nonlocal snapshot
                phase('export-check')
                # FileComplete is asynchronous: wait for the directory to appear.
                for _ in range(40):
                    if await exists(afc, exported):
                        break
                    await asyncio.sleep(0.1)
                node = await exists(afc, exported)
                if node is None and recovery and payload is not None:
                    phase('recovery-final-authorized')
                    return
                require(node and node['st_ifmt'] == 'S_IFDIR',
                        'iPhone не отдал текущие настройки оператора. Не повторяйте установку: '+recover_hint()+'.')
                phase('original-exported')
                snapshot = await remote_tree(afc, exported)
                write_tree_zip(run / 'original.zip', snapshot)
                phase('backup-saved', original_hash=tree_hash(snapshot))
                if expected is not None:
                    # expected: the exact catalog, or a check for when only part of it is known.
                    require(expected(snapshot) if callable(expected) else snapshot == expected, 'Настройки оператора на iPhone изменились во время операции. Запись отменена: '+recover_hint()+'.')
                require(await remote_tree(afc, exported) == snapshot, 'Export changed after backup')
                phase('final-authorized')
            phase('host-started')
            async with device_log(device, run / 'device.log'):
                await host_session(device.udid, assets, pause, run)
            # The phone may take several seconds to move the final asset after the session ends.
            for _ in range(150):
                if await exists(afc, final_source) is None:
                    break
                await asyncio.sleep(0.1)
            require(await exists(afc, final_source) is None, 'Final source not consumed; operation unconfirmed')
            phase('placement-observed', complete=True, requires_recovery=False)
        except BaseException as error:
            journal['operation_error'] = str(error)
            save_json(run / 'journal.json', journal)
            raise
        finally:
            if mutated:
                try:
                    # Its own limit: the transfer timeout may already have fired on a dead connection.
                    async with network_timeout(NETWORK_BOOKS_SECONDS):
                        other = await restore_books(afc, books, books_existed, books_top)
                    journal['books_restored'] = True
                    if other: journal['books_other_changes'] = other[:50]
                except Exception as e:
                    journal['books_restored'] = False
                    journal['books_restore_error'] = str(e)
                    save_json(run / 'journal.json', journal)
                    if journal.get('complete'):
                        raise RuntimeError('Каталог операторов записан и проверен, не удалось только вернуть '
                                           'служебные файлы Books: ' + str(e)) from e
                    raise
                save_json(run / 'journal.json', journal)
    # Remote originals and staging identifiers are intentionally retained for recovery.
    return snapshot

async def connect(udid):
    from pymobiledevice3.lockdown import create_using_usbmux
    return await asyncio.wait_for(create_using_usbmux(serial=udid, autopair=False, connection_type=CONNECTION), 15)

async def device_info(device):
    result = {k: await device.get_value(key=k) for k in
              ('ProductType', 'HardwareModel', 'ProductVersion', 'BuildVersion', 'ActivationState')}
    rows = await device.get_value(key='CarrierBundleInfoArray') or []
    result['carriers'] = [{k: r[k] for k in ('MCC', 'MNC', 'Slot', 'CFBundleIdentifier', 'CFBundleVersion') if k in r}
                          for r in rows]
    return result

def check_trigger(path, sims, targets=(BUNDLE,)):
    require(path.suffix == '.ipcc', 'Trigger must be an IPCC')
    tree = read_tree_zip(path)
    bundles = {n.split('/')[1] for n in tree if n.startswith('Payload/') and len(n.split('/')) > 1
               and n.split('/')[1].endswith('.bundle')}
    require(len(bundles) == 1, 'Trigger must contain exactly one bundle')
    name = bundles.pop()
    inner = {n.removeprefix('Payload/'): v for n, v in tree.items() if n.startswith('Payload/')}
    info, carrier = bundle_info(inner, name)
    require(name not in targets, 'Триггер совпадает с устанавливаемым профилем '+name+'; нужен другой IPCC')
    require(info.get('CFBundleIdentifier') != 'com.apple.Viva_kw', 'Viva is not an independent trigger')
    identifiers = carrier.get('SupportedSIMs', [])
    require(identifiers and all(isinstance(s, str) and re.fullmatch(r'\d{5,6}(?:_.*)?', s) for s in identifiers),
            'Unknown SupportedSIMs format in trigger')
    affected = set(identifiers)
    for n, (k, _) in tree.items():
        if k == 'l':
            leaf = n.split('/')[-1]
            require(re.fullmatch(r'\d{5,6}(?:_.*)?', leaf), 'Unexpected trigger symlink')
            affected.add(leaf)
    require(not any(a == s or a.startswith(s + '_') for a in affected for s in sims),
            'Trigger overlaps an installed SIM; select a different carrier')
    return {'bundle': name, 'version': info.get('CFBundleVersion'), 'sha256': digest(path.read_bytes())}

async def install_trigger(device, path, run):
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    # Override upstream extraction to preserve raw bytes without creating local symlinks.
    class Installer(InstallationProxyService):
        async def _upload_ipcc(self, file_stream, afc_client, dst):
            with zipfile.ZipFile(file_stream) as z:
                for entry in z.infolist():
                    target = dst + '/' + entry.filename
                    await afc_client.makedirs(target if entry.is_dir() else target.rsplit('/', 1)[0])
                    if not entry.is_dir():
                        await afc_client.set_file_contents(target, z.read(entry))
    status = {'ipcc_installation_completed': False, 'log_error': None, 'nr_data_verified': False}
    try:
        async with syslog_capture(device, run / 'commcenter.log', lambda line: 'CommCenter' in line, status, linger=0):
            try:
                async with Installer(device) as installer:
                    await asyncio.wait_for(installer.install_from_local(path), 90)
            except Exception as error:
                if 'InstallProhibited' in f'{type(error).__name__} {error}':
                    raise RuntimeError('iPhone запрещает установку (InstallProhibited). Проверьте «Настройки → '
                                       'Экранное время → Ограничения контента и конфиденциальности → Покупки '
                                       'в iTunes Store и App Store → Установка приложений: Да» и профили '
                                       'управления (MDM). Ничего на телефоне не изменено.') from error
                raise
            status['ipcc_installation_completed'] = True
            save_json(run / 'installation.json', status)
            await asyncio.sleep(8)
    except BaseException as error:
        status['installation_error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        save_json(run / 'installation.json', status)
    return status

# AirTraffic protocol follows the MIT-licensed AirLift host sequence.
# Native Apple calls run in a disposable subprocess: a blocked DLL cannot hang recovery.
import ctypes as C
import subprocess
import uuid
from datetime import datetime

APPLE_DIRS = []
ASSET_SHA256 = '6de1ea0be81a29c145ef414f24bc21d1dcb8a4eb737b22b1f956e9a6f0c2098b'
APPLE_DLL_CACHE = ROOT / '.apple-dlls'
_SUSPECT_APPLE_DIR = ('anisette', 'ipa_downloader', 'sideloadly', 'altstore')


def _suspect_apple_dir(path):
    low = str(path).replace('\\', '/').lower()
    return any(m in low for m in _SUSPECT_APPLE_DIR)


def _apple_access_denied(exc):
    if isinstance(exc, PermissionError):
        return True
    if getattr(exc, 'winerror', None) == 5:
        return True
    msg = str(exc).lower()
    return 'access is denied' in msg or 'отказано в доступе' in msg or '[winerror 5]' in msg


def windows_apple_library_dirs(extra=()):
    """Dirs with AirTrafficHost/CoreFoundation: --apple-dir, classic AMDS, Apple Devices, Store iTunes."""
    import winreg
    extras = [Path(p).resolve() for p in extra]
    paths = []
    for key in ('CommonProgramW6432', 'CommonProgramFiles'):
        base = os.environ.get(key)
        if base:
            paths += [Path(base)/'Apple'/'Mobile Device Support',
                      Path(base)/'Apple'/'Apple Application Support']
    def reg_str(hive, subkey, name, access=0):
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | access) as k:
                value, typ = winreg.QueryValueEx(k, name)
                return value if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and value else None
        except OSError:
            return None
    for access in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY, 0):
        for sub, names in (
            (r'SOFTWARE\Apple Inc.\Apple Mobile Device Support', ('InstallDir', 'InstallPath')),
            (r'SOFTWARE\Apple Inc.\Apple Application Support', ('InstallDir', 'InstallPath')),
            (r'SOFTWARE\WOW6432Node\Apple Inc.\Apple Mobile Device Support', ('InstallDir', 'InstallPath')),
            (r'SOFTWARE\WOW6432Node\Apple Inc.\Apple Application Support', ('InstallDir', 'InstallPath'))):
            for name in names:
                value = reg_str(winreg.HKEY_LOCAL_MACHINE, sub, name, access)
                if value:
                    paths.append(Path(os.path.expandvars(value)))
    # Store: HKCR\Local Settings\...\PackageRepository\Packages
    pkg_root = r'Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages'
    devices_dirs, itunes_dirs = [], []
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, pkg_root) as root:
            i = 0
            while True:
                try: name = winreg.EnumKey(root, i)
                except OSError: break
                i += 1
                low = name.lower()
                if '_neutral_' in low or '_x86_' in low: continue
                is_devices = low.startswith('appleinc.appledevices_')
                is_itunes = low.startswith('appleinc.itunes_')
                if not (is_devices or is_itunes): continue
                try:
                    with winreg.OpenKey(root, name) as pkg:
                        try: path_val, _ = winreg.QueryValueEx(pkg, 'Path')
                        except OSError: path_val = None
                        if not path_val:
                            try: path_val = winreg.QueryValue(pkg, None)
                            except OSError: path_val = None
                except OSError:
                    continue
                if not path_val: continue
                base = Path(path_val)
                if is_devices:
                    devices_dirs.append(base)  # 64-bit DLLs in package root
                else:
                    itunes_dirs += [base/'AMDS64', base]
    except OSError:
        pass
    paths += devices_dirs + itunes_dirs
    # Skip third-party anisette/IPA caches from discovery; keep explicit --apple-dir.
    paths = [p for p in paths if p.is_dir() and not _suspect_apple_dir(p)]
    return list(dict.fromkeys(p for p in extras + paths if p.is_dir()))


def windows_apple_cohesive_dir(extra=()):
    """One directory that contains both CoreFoundation.dll and AirTrafficHost.dll."""
    dirs = windows_apple_library_dirs(extra)
    extras = {Path(p).resolve() for p in extra}
    def rank(d):
        s = str(d).replace('\\', '/').lower()
        if d in extras: return 0
        if 'mobile device support' in s and 'windowsapps' not in s: return 1
        if 'appleinc.appledevices_' in s: return 2
        if s.endswith('/amds64') or '/amds64/' in s: return 3
        if 'appleinc.itunes_' in s: return 4
        return 5
    both = [d for d in dirs
            if (d/'CoreFoundation.dll').is_file() and (d/'AirTrafficHost.dll').is_file()]
    both.sort(key=rank)
    return (both[0] if both else None), dirs


def ensure_apple_dll_cache(source):
    """Copy readable *.dll from source into ROOT/.apple-dlls (refresh on size/mtime change)."""
    import shutil
    cache = APPLE_DLL_CACHE
    cache.mkdir(parents=True, exist_ok=True)
    for src in source.glob('*.dll'):
        dst = cache / src.name
        try:
            st = src.stat()
        except OSError:
            continue
        try:
            if dst.is_file():
                dt = dst.stat()
                if dt.st_size == st.st_size and int(dt.st_mtime) == int(st.st_mtime):
                    continue
            shutil.copy2(src, dst)
        except OSError:
            continue
    need = ('CoreFoundation.dll', 'AirTrafficHost.dll')
    if not all((cache / n).is_file() for n in need):
        raise RuntimeError(
            'WindowsApps ACL заблокировал чтение/загрузку DLL Apple '
            f'({source}). Установите классический Apple Mobile Device Support '
            'или скопируйте папку DLL Apple Devices / AMDS в обычный каталог '
            'и укажите его через --apple-dir (либо исправьте ACL и повторите).')
    return cache


class AppleHost:
    def __init__(self, directories=()):
        self.handles = []
        self.pool = None
        if sys.platform == 'darwin':
            self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
            self.at = C.CDLL('/System/Library/PrivateFrameworks/AirTrafficHost.framework/AirTrafficHost')
            self.objc = C.CDLL('/usr/lib/libobjc.A.dylib')
            self.objc.objc_autoreleasePoolPush.restype = C.c_void_p
            self.objc.objc_autoreleasePoolPush.argtypes = []
            self.objc.objc_autoreleasePoolPop.argtypes = [C.c_void_p]
            self.objc.objc_autoreleasePoolPop.restype = None
            self.pool = self.objc.objc_autoreleasePoolPush()
        elif sys.platform == 'win32':
            require(C.sizeof(C.c_void_p) == 8, 'Нужен 64-битный Python и 64-битные компоненты Apple.')
            source, _ = windows_apple_cohesive_dir(directories)
            require(source, 'Не найден каталог с CoreFoundation.dll и AirTrafficHost.dll вместе. '
                    'Установите Apple Devices из Microsoft Store или Apple Mobile Device Support '
                    '(и драйвер Apple Mobile Device USB). Либо скопируйте папку DLL в обычный путь '
                    'и укажите её через --apple-dir.')
            def load_pair(load_dir):
                self.handles.append(os.add_dll_directory(str(load_dir)))
                return (C.CDLL(str(load_dir/'CoreFoundation.dll'), winmode=0x1100),
                        C.CDLL(str(load_dir/'AirTrafficHost.dll'), winmode=0x1100))
            try:
                self.cf, self.at = load_pair(source)
            except OSError as e:
                if not _apple_access_denied(e):
                    raise RuntimeError('Библиотеки Apple недоступны: ' + str(e)) from e
                for h in self.handles:
                    with contextlib.suppress(Exception):
                        h.close()
                self.handles.clear()
                cache = ensure_apple_dll_cache(source)
                try:
                    self.cf, self.at = load_pair(cache)
                except OSError as e2:
                    raise RuntimeError(
                        'WindowsApps ACL заблокировал загрузку DLL Apple даже из кэша .apple-dlls. '
                        'Установите классический Apple Mobile Device Support или скопируйте папку '
                        'DLL Apple Devices / AMDS в обычный каталог и укажите через --apple-dir.') from e2
        else:
            raise RuntimeError('Поддерживаются macOS и Windows.')
        P, I, U = C.c_void_p, C.c_ssize_t, C.c_size_t
        def bind(lib, name, result, args):
            f = getattr(lib, name); f.restype = result; f.argtypes = args
        for name, result, args in [
            ('CFDataCreate', P, [P,P,I]), ('CFDataGetLength', I, [P]),
            ('CFDataGetBytePtr', P, [P]), ('CFRelease', None, [P]),
            ('CFPropertyListCreateWithData', P, [P,P,U,P,P]),
            ('CFPropertyListCreateData', P, [P,P,I,U,P])]:
            bind(self.cf, name, result, args)
        for name, result, args in [
            ('ATHostConnectionCreate', P, [P]), ('ATHostConnectionRelease', None, [P]),
            ('ATHostConnectionReadMessage', P, [P]),
            ('ATHostConnectionSendHostInfo', None, [P,P]),
            ('ATHostConnectionSendSyncRequest', None, [P,P,P,P]),
            ('ATHostConnectionSendMetadataSyncFinished', None, [P,P,P]),
            ('ATHostConnectionSendAssetCompleted', None, [P,P,P,P]),
            ('ATCFMessageGetName', P, [P]), ('ATCFMessageGetParam', P, [P,P])]:
            bind(self.at, name, result, args)

    def encode(self, value):
        raw = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
        buf = C.create_string_buffer(raw)
        data = self.cf.CFDataCreate(None, buf, len(raw))
        require(data, 'CFDataCreate failed')
        try:
            result = self.cf.CFPropertyListCreateWithData(None, data, 0, None, None)
            require(result, 'CFPropertyListCreateWithData failed')
            return result
        finally:
            self.cf.CFRelease(data)

    def decode(self, value):
        require(value, 'Пустое сообщение Apple')
        data = self.cf.CFPropertyListCreateData(None, value, 200, 0, None)
        require(data, 'CFPropertyListCreateData failed')
        try:
            size = self.cf.CFDataGetLength(data)
            require(0 <= size <= MAX_BYTES, 'Слишком большое сообщение Apple')
            return plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data), size))
        finally:
            self.cf.CFRelease(data)

    def call(self, name, connection, *values):
        refs = []
        try:
            for v in values: refs.append(self.encode(v))
            return getattr(self.at, name)(connection, *refs)
        finally:
            for ref in refs: self.cf.CFRelease(ref)

    def close(self):
        if self.pool:
            self.objc.objc_autoreleasePoolPop(self.pool); self.pool = None


def framed(value):
    print('CARRIER_SWAP_JSON:' + json.dumps(value), flush=True)


def native_host(udid, assets, directories):
    host = AppleHost(directories)
    connection = None
    try:
        sample = {'test': ['Book', 1, False]}
        ref = host.encode(sample)
        try: require(host.decode(ref) == sample, 'Ошибка обмена с CoreFoundation')
        finally: host.cf.CFRelease(ref)
        if udid is None:
            framed({'ok': True, 'deviceConnections': 0}); return
        ref = host.encode(udid)
        try: connection = host.at.ATHostConnectionCreate(ref)
        finally: host.cf.CFRelease(ref)
        require(connection, 'Не удалось открыть AirTraffic. Закройте синхронизацию Finder/iTunes/Apple Devices.')
        def until(wanted, limit):
            for _ in range(limit):
                msg = host.at.ATHostConnectionReadMessage(connection)
                if not msg: continue
                try:
                    name = host.decode(host.at.ATCFMessageGetName(msg))
                    try: body = json.dumps(host.decode(msg), ensure_ascii=False, default=str)[:4000]
                    except Exception as e: body = 'не прочитано: ' + str(e)
                    framed({'event': 'message', 'name': name, 'body': body})
                    if name == wanted:
                        if name != 'AssetManifest': return True
                        key = host.encode('AssetManifest')
                        try: return host.decode(host.at.ATCFMessageGetParam(msg, key))
                        finally: host.cf.CFRelease(key)
                    require(name not in ('SyncFailed','SyncFinished'), 'Синхронизация закончилась преждевременно')
                finally: host.cf.CFRelease(msg)
            raise RuntimeError('Не получено сообщение ' + wanted)
        until('SyncAllowed', 8)
        info = {'Type':'iTunes', 'Version':'13.7.0.161', 'SyncHostName':'CarrierSIM',
                'LibraryID':str(uuid.uuid4()), 'SyncedDataclasses':['Book'],
                'SyncedAssetTypes':['Book'], 'Wakeable':False}
        if sys.platform == 'darwin':
            import platform
            info['MacOSVersion'] = platform.mac_ver()[0]
        host.call('ATHostConnectionSendHostInfo', connection, info)
        time.sleep(.2)
        host.call('ATHostConnectionSendSyncRequest', connection, ['Book'], {}, info)
        until('ReadyForSync', 12)
        host.call('ATHostConnectionSendMetadataSyncFinished', connection, {'Book':1}, {})
        manifest = until('AssetManifest', 20)
        require(isinstance(manifest,dict), 'Неверный манифест AirTraffic')
        books = [r for r in manifest.get('Book',[]) if isinstance(r,dict)]
        found = {r.get('AssetID') for r in books if r.get('IsDownload')}
        missing = [a for a,_ in assets if a not in found]
        if missing:
            # Keep what the phone actually answered: host.jsonl in the run folder.
            framed({'event':'manifest','dataclasses':sorted(map(str,manifest)),'expected':[a for a,_ in assets],
                    'book':[{k:str(v) for k,v in r.items()} for r in books[:50]]})
            raise RuntimeError(f'AirTraffic не подтвердил нужные объекты: iPhone вернул {len(books)} '
                               f'объект(ов) Book, не хватает {len(missing)} из {len(assets)}')
        for i,(identifier,destination) in enumerate(assets):
            if i == 2:
                framed({'event':'before-final-asset'})
                require(sys.stdin.readline().strip() == 'CONTINUE', 'Резервная копия не подтверждена')
            host.call('ATHostConnectionSendAssetCompleted', connection, identifier, 'Book', destination)
            if i+1 < len(assets): time.sleep(.9)
        time.sleep(6)
        framed({'ok':True})
    finally:
        if connection: host.at.ATHostConnectionRelease(connection)
        host.close()


def host_command():
    return [sys.executable, str(Path(__file__).resolve()), '--_host']


async def host_session(udid, assets, callback, run):
    config = run/'host-input.json'
    save_json(config, {'udid':udid, 'assets':assets, 'directories':APPLE_DIRS})
    proc = await asyncio.create_subprocess_exec(*host_command(), str(config),
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    async def stderr():
        with (run/'host.stderr').open('wb') as f:
            while data := await proc.stderr.read(4096): f.write(data)
    task = asyncio.create_task(stderr())
    paused = False; result = None
    try:
        with (run/'host.jsonl').open('wb') as log:
            async with asyncio.timeout(170):
                while line := await proc.stdout.readline():
                    log.write(line); log.flush()
                    if not line.startswith(b'CARRIER_SWAP_JSON:'): continue
                    row = json.loads(line[len(b'CARRIER_SWAP_JSON:'):])
                    if row.get('event') == 'before-final-asset':
                        require(not paused, 'Повторная пауза AirTraffic')
                        await callback(); paused = True
                        proc.stdin.write(b'CONTINUE\n'); await proc.stdin.drain()
                    elif 'ok' in row: result = row
                code = await proc.wait()
        detail = (result or {}).get('error') or ('код ' + str(code))
        require(code == 0 and paused and result and result.get('ok'), 'Сбой AirTraffic: ' + str(detail))
    finally:
        if proc.returncode is None:
            proc.kill(); await proc.wait()
        await task
        config.unlink(missing_ok=True)

TARGET_BUNDLES = ('Vodafone_hu.bundle',)
SYSTEM_PREFIX = '../../../../../../System/Library/Carrier Bundles/iPhone/'
MODELS = {'iPhone14,7': {'name': 'iPhone 14', 'boards': ['D27AP']}, 'iPhone14,8': {'name': 'iPhone 14 Plus', 'boards': ['D28AP']}, 'iPhone15,2': {'name': 'iPhone 14 Pro', 'boards': ['D73AP']}, 'iPhone15,3': {'name': 'iPhone 14 Pro Max', 'boards': ['D74AP']}, 'iPhone15,4': {'name': 'iPhone 15', 'boards': ['D37AP']}, 'iPhone15,5': {'name': 'iPhone 15 Plus', 'boards': ['D38AP']}, 'iPhone16,1': {'name': 'iPhone 15 Pro', 'boards': ['D83AP']}, 'iPhone16,2': {'name': 'iPhone 15 Pro Max', 'boards': ['D84AP']}, 'iPhone17,4': {'name': 'iPhone 16 Plus', 'boards': ['D48AP']}, 'iPhone17,2': {'name': 'iPhone 16 Pro Max', 'boards': ['D94AP']}, 'iPhone17,3': {'name': 'iPhone 16', 'boards': ['D47AP']}, 'iPhone17,1': {'name': 'iPhone 16 Pro', 'boards': ['D93AP']}, 'iPhone17,5': {'name': 'iPhone 16e', 'boards': ['V59AP']}, 'iPhone18,1': {'name': 'iPhone 17 Pro', 'boards': ['V53AP']}, 'iPhone18,2': {'name': 'iPhone 17 Pro Max', 'boards': ['V54AP']}, 'iPhone18,4': {'name': 'iPhone Air', 'boards': ['D23AP']}, 'iPhone18,3': {'name': 'iPhone 17', 'boards': ['V57AP']}, 'iPhone18,5': {'name': 'iPhone 17e', 'boards': ['V159AP']}, 'iPhone19,7': {'name': 'iPhone 18 Pro Max', 'boards': ['V64SAP']}, 'iPhone19,3': {'name': 'iPhone 18 Pro Max (U.S.)', 'boards': ['V64AP']}, 'iPhone19,2': {'name': 'iPhone 18 Pro', 'boards': ['V63AP']}}


def load_assets():
    path = ROOT/'assets.zip'
    require(digest(path.read_bytes()) == ASSET_SHA256, 'Архив assets.zip повреждён или заменён.')
    tree = read_tree_zip(path)
    return tree


def bundle_link(name):
    require(re.fullmatch(r'[A-Za-z0-9_]+\.bundle', name), 'Неверное имя пакета: '+name)
    return ('l', (SYSTEM_PREFIX+name).encode())


SLOT_NAMES = {'kOne': 'SIM 1', 'kTwo': 'SIM 2'}
# Exit code for "written, but iOS did not confirm the chosen bundle"; 2 is argparse's usage error.
UNCONFIRMED = 3
SLOT_CHOICES = {'1': ('kOne',), '2': ('kTwo',), 'all': ('kOne', 'kTwo')}


CONFIG = ROOT / 'bundle.yaml'


def load_bundle_config(path=CONFIG):
    # A tiny subset of YAML: "default: Name" and "MCCMNC: Name", comments with #.
    config = {}
    if path.exists():
        for number, raw in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
            line = raw.split('#', 1)[0].strip()
            if not line: continue
            match = re.fullmatch(r'["\']?(default|\d{5,6})["\']?\s*:\s*["\']?([A-Za-z0-9_]+?)(?:\.bundle)?["\']?', line)
            require(match, f'{path.name}, строка {number}: ожидается «default: Vodafone_hu» или «25001: Vodafone_hu» '
                           '(MCCMNC без пробела, имя пакета латиницей).')
            key, name = match.groups()
            require(key not in config, f'{path.name}, строка {number}: {key} указан дважды.')
            config[key] = name + '.bundle'
    config.setdefault('default', BUNDLE)
    return config


def bundle_for(plmn, config):
    return config.get(plmn) or config.get('default') or BUNDLE


OPERATORS = {'232-05': 'One', '250-01': 'МТС', '250-02': 'МегаФон', '250-11': 'Yota', '250-20': 'T2',
             '250-99': 'Билайн', '257-01': 'A1', '257-02': 'МТС BY', '257-04': 'life:)'}


def mask_phone(phone):
    clean = re.sub(r'[^\d+]', '', phone) if isinstance(phone, str) else ''
    if not clean.startswith('+') or len(clean) < 8:
        return 'номер недоступен'
    code = 2 if clean.startswith(('+7', '+1')) else 4 if clean.startswith(
        ('+375', '+992', '+993', '+994', '+995', '+996', '+998')) else 3
    return f'{clean[:code]} ••• •••{clean[-4:]}'


def sim_line(row, top):
    # What the user can match against Settings: operator, SIM type, ICCID tail, masked number,
    # and the bundle iOS actually loaded (an IMSI link shows up here too).
    slot = row.get('Slot')
    plmn = f"{row.get('MCC', '')}-{row.get('MNC', '')}"
    operator = f'{OPERATORS[plmn]} ({plmn})' if plmn in OPERATORS else plmn
    tray_empty = 'Absent' in str(top.get('SIMTrayStatus', ''))
    embedded = top.get('SIM1IsEmbedded') if slot == 'kOne' else None
    kind = ('eSIM' if embedded or (embedded is None and tray_empty) else
            'физ. SIM' if embedded is False else 'тип неизвестен')
    iccid = str(row.get('IntegratedCircuitCardIdentity', ''))
    # Lockdown reports the phone number of one line only; show it for the SIM it belongs to.
    phone = (mask_phone(top.get('PhoneNumber')) if iccid and iccid == str(top.get('IntegratedCircuitCardIdentity', ''))
             else 'номер недоступен')
    current = str(row.get('CFBundleIdentifier', '')).removeprefix('com.apple.') or 'неизвестно'
    return '  ·  '.join((SLOT_NAMES.get(slot, str(slot)), operator, kind,
                         f'ICCID …{iccid[-4:]}' if len(iccid) >= 4 else 'ICCID недоступен', phone, 'сейчас: ' + current))


def select_sims(rows, config=None, slots=SLOT_CHOICES['all']):
    selected = []; seen_slots = set(); seen_imsi = set()
    for row in rows:
        mcc, mnc = str(row.get('MCC','')), str(row.get('MNC',''))
        slot, imsi = row.get('Slot'), row.get('InternationalMobileSubscriberIdentity')
        require(slot in ('kOne','kTwo') and slot not in seen_slots, 'Неоднозначные слоты SIM; запись отменена.')
        seen_slots.add(slot)
        if slot not in slots: continue
        require(re.fullmatch(r'\d{3}',mcc) and re.fullmatch(r'\d{2,3}',mnc) and isinstance(imsi,str) and
                re.fullmatch(r'\d{15}',imsi) and imsi.startswith(mcc+mnc),
                'iPhone не сообщил полный IMSI для SIM '+mcc+mnc+'. Включите линию и разблокируйте телефон.')
        require(imsi not in seen_imsi, 'Один IMSI указан в двух слотах; запись отменена.')
        seen_imsi.add(imsi)
        selected.append({'slot':slot,'plmn':mcc+mnc,'imsi':imsi,'bundle':bundle_for(mcc+mnc, config or {})})
    missing = [SLOT_NAMES[s] for s in slots if s not in seen_slots]
    require(len(slots) > 1 or not missing, missing and missing[0]+' не найдена в iPhone. Выберите другую SIM.')
    require(selected, 'Телефон не сообщил ни одной SIM с доступным IMSI.')
    return selected


def make_plan(original, sims):
    desired = dict(original)
    # Signed system bundles match the phone's own firmware; only exact IMSI aliases change.
    for sim in sims:
        n = sim['imsi']
        require(n not in original or original[n][0]=='l', 'Вместо ссылки IMSI обнаружен файл или каталог.')
        desired[n] = bundle_link(sim['bundle'])
    validate_tree(desired)
    return desired


def imsi_links(tree):
    # This installer creates root-level, 15-digit IMSI aliases, never directories.
    return {n:v for n,v in tree.items() if v[0]=='l' and re.fullmatch(r'\d{15}',n)}


def remove_imsi_links(original, only=None):
    # only: the IMSIs to remove; None removes every IMSI alias.
    links = {n for n in imsi_links(original) if only is None or n in only}
    result = {n:v for n,v in original.items() if n not in links}
    validate_tree(result)
    return result


def check_phone(info):
    model = MODELS.get(info['ProductType'])
    if (not model or str(info['HardwareModel']).upper() not in model['boards']
            or info['ProductVersion'] != '27.0'
            or info['BuildVersion'] not in ('24A435', '24A437')):
        print('Предупреждение: модель, плата или версия iOS не проверена. '
              'Скрипт МОЖЕТ не работать. Продолжаю без ограничения совместимости.', flush=True)
    require(info['ActivationState']=='Activated','iPhone не активирован.')


async def choose_device(udid, wait_seconds=180):
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError, NoDeviceConnectedError
    deadline=time.monotonic()+wait_seconds
    announced=False
    while True:
        try:
            # One phone on Wi-Fi and Ethernet (or IPv4 and IPv6) is listed more than once.
            devices=list(dict.fromkeys(d.serial for d in await list_devices() if d.connection_type==CONNECTION))
        except (OSError, ConnectionError, ConnectionFailedToUsbmuxdError, NoDeviceConnectedError):devices=[]
        if udid and udid in devices:return udid
        if not udid and len(devices)==1:return devices[0]
        require(udid or len(devices)<2,'Подключено несколько iPhone. Укажите --udid.')
        if not announced:
            print('Ожидаю iPhone по Wi-Fi. Телефон и компьютер должны быть в одной сети, iPhone разблокирован…'
                  if CONNECTION=='Network' else 'Ожидаю подключения iPhone по USB. Подключите и разблокируйте телефон…',flush=True)
            announced=True
        require(time.monotonic()<deadline,'Время ожидания подключения истекло. '+
                ('iPhone не виден по Wi-Fi: один раз подключите его кабелем и включите в '
                 + ('Apple Devices (или iTunes) ' if sys.platform=='win32' else 'Finder/iTunes ')
                 + '«Показывать этот iPhone, если он подключён к Wi-Fi», затем повторите с --wifi.' if CONNECTION=='Network' else
                 'Проверьте кабель и повторите.')+
                (' Если iPhone виден в Проводнике, но скрипт его не находит, не установлен драйвер Apple Mobile '
                 'Device USB: см. раздел «Windows не видит iPhone» в README.' if sys.platform=='win32' and CONNECTION=='USB' else ''))
        await asyncio.sleep(min(2,max(0,deadline-time.monotonic())))


async def ready_device(udid, wait_seconds):
    from pymobiledevice3 import exceptions as errors
    deadline=time.monotonic()+wait_seconds
    last=None;asked=False;unpaired=0
    while True:
        await choose_device(udid,max(0,deadline-time.monotonic()))
        try:
            device=await connect(udid)
            if not device.paired and CONNECTION=='Network':
                # Trust can only be granted over the cable; Wi-Fi reuses the existing pair record.
                # A Wi-Fi drop during StartSession or TLS also reads as unpaired, so retry a few times.
                await device.close()
                unpaired+=1
                require(unpaired<3 and time.monotonic()<deadline,
                        'Нет доверия с этим компьютером. Подключите iPhone кабелем, запустите без --wifi '
                        'и нажмите «Доверять», затем повторите с --wifi.')
                await asyncio.sleep(2)
                continue
            if not device.paired:
                # No pair record on this computer: without pairing lockdown answers GetProhibited.
                # pymobiledevice3 saves the new record to usbmuxd too, so Apple's AirTrafficHost can use it.
                try:
                    if not asked:
                        print('На iPhone появится запрос «Доверять этому компьютеру?». '
                              'Нажмите «Доверять» и введите код-пароль.',flush=True)
                        asked=True
                    await device.pair(timeout=max(1,deadline-time.monotonic()))
                    require(await device.validate_pairing(),'Не удалось установить доверие с iPhone. Отключите кабель и повторите.')
                except errors.UserDeniedPairingError:
                    await device.close()
                    raise RuntimeError('На iPhone выбрано «Не доверять». Отключите и снова подключите кабель, '
                                       'затем нажмите «Доверять».') from None
                except BaseException:
                    await device.close();raise
            return device
        except (OSError, errors.ConnectionTerminatedError, errors.PasswordRequiredError,
                errors.NotPairedError, errors.PairingDialogResponsePendingError,
                errors.ConnectionFailedError, errors.InvalidConnectionError) as error:
            if last is None:print('Ожидаю разблокировки, доверия и готовности '+
                                  ('соединения по Wi-Fi…' if CONNECTION=='Network' else 'USB-соединения…'),flush=True)
            last=error
            if time.monotonic()>=deadline:raise RuntimeError('iPhone не готов: разблокируйте и подтвердите доверие.') from error
            await asyncio.sleep(2)


def transient_error(error):
    from pymobiledevice3 import exceptions as errors
    if isinstance(error,(ConnectionError,TimeoutError,errors.ConnectionTerminatedError,
                         errors.ConnectionFailedError,errors.InvalidConnectionError)):
        return True
    # Broken pipe, reset, timeout; network down/unreachable, host down/unreachable (macOS, then Windows).
    if isinstance(error,OSError) and error.errno in (32,54,60,104,110,50,51,64,65,
                                                     10050,10051,10054,10060,10064,10065):return True
    # The phone answering without our assets is deterministic: retrying only repeats it.
    return isinstance(error,RuntimeError) and any(t in str(error) for t in
        ('Сбой AirTraffic','Final source not consumed')) and 'не подтвердил нужные объекты' not in str(error)


async def execute_with_retry(args,assets):
    # Once selected, reconnect only to this exact phone, even if a different phone appears.
    args.udid=await choose_device(args.udid,args.wait_seconds)
    if args.diagnose or args.watch_call:
        # Read-only: no retries and no auto-recovery, which would write to the phone.
        return await diagnostics(args)
    for attempt in range(1,args.attempts+1):
        print(f'Попытка {attempt} из {args.attempts}',flush=True)
        before=set(pending(args.runs,args.udid))
        try:return await execute(args,assets)
        except Exception as error:
            # Roll back after any failure; retry only when a new attempt can change the outcome.
            # --status only reads: its failure must never start a recovery that writes to the phone.
            # Stages left by earlier launches are rolled back only when recovery was asked for.
            failed=[] if args.status else [p for p in pending(args.runs,args.udid) if args.recover or p not in before]
            if failed:
                print('Сбой во время записи. Сначала возвращаю iPhone в исходное состояние…',flush=True)
                device=await ready_device(args.udid,args.wait_seconds)
                recovery=args.runs/(datetime.now().strftime('%Y%m%d-%H%M%S-')+'auto-recovery-'+uuid.uuid4().hex[:6])
                recovery.mkdir(mode=0o700); save_environment(recovery)
                try:
                    await recover_all(device,failed,recovery)
                    print('iPhone возвращён в исходное состояние.',flush=True)
                except BaseException:
                    print('Автовосстановление не завершено. Журнал:',recovery,flush=True)
                    print('Не удаляйте папку runs и '+recover_hint()+'.',flush=True)
                    raise
                finally:await device.close()
            if attempt==args.attempts or not transient_error(error):raise
            print('Повторяю попытку…',flush=True)
            await asyncio.sleep(2)


BUNDLE_BLOCK = '----------Bundle File----------'


def report_log(path, sims):
    results = {s['slot']:{'slot':s['slot'],'plmn':s['plmn'],'expected':s['bundle'],
                         'selected':None,'verified':False} for s in sims}
    if path.exists():
        for block in path.read_text(encoding='utf-8',errors='replace').split(BUNDLE_BLOCK):
            resolved = re.findall(r'Resolved path\s*:\s*([^\r\n]+)',block)
            linked = re.findall(r'Linking Path\s*:\s*([^\r\n]+)',block)
            verified = re.findall(r'Verification Result\s*:\s*([^\r\n]+)',block)
            if len(resolved)!=1 or len(linked)!=1: continue
            for slot,index in (('kOne',1),('kTwo',2)):
                if slot in results and linked[0].strip().endswith(f'/Carrier{index}Bundle.bundle'):
                    results[slot].update(selected=resolved[0].strip().rsplit('/',1)[-1],
                                         verified=verified==['Success'])
    return list(results.values())


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def pending(runs, udid):
    # Oldest first: run folders start with a timestamp; stages inside one run by journal age.
    journals = sorted(runs.glob('*/*/journal.json'), key=lambda p: (p.parent.parent.name, p.stat().st_mtime))
    return [p.parent for p in journals
            if (j:=read_json(p)).get('udid_hash')==digest(udid.encode())
            and (j.get('requires_recovery') or j.get('books_restored') is False) and not j.get('recovered_by')]


@contextlib.contextmanager
def operation_lock(runs):
    runs.mkdir(parents=True,exist_ok=True)
    with (runs/'.lock').open('a+b') as f:
        # Append mode: write the lockable byte only once, not on every launch.
        if f.seek(0,2)==0: f.write(b'0'); f.flush()
        f.seek(0)
        try:
            if sys.platform=='win32':
                import msvcrt
                msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError('Скрипт уже запущен в другом окне. Дождитесь его завершения или закройте его.') from None
        try: yield
        finally:
            if sys.platform=='win32':
                f.seek(0); msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)


def bound(record,device):
    require(record.get('target')==TARGET and record.get('udid_hash')==digest(device.udid.encode()),
            'Копия относится к другому телефону или каталогу.')


EXPORT_SETTLE_SECONDS = 60


async def recover_stage(device, failed, run, tag=''):
    from pymobiledevice3.services.afc import AfcService
    record = read_json(failed/'journal.json'); bound(record,device)
    if record.get('recovered_by'):
        print('Этап уже восстановлен:',record['recovered_by'],flush=True)
        return
    remote = record.get('exported','')
    require(re.fullmatch(r'airlift-saved-[a-f0-9]{20}',remote),'Неверный путь восстановления.')
    books = read_tree_zip(failed/'books.zip'); state=read_json(failed/'books.json')
    require(tree_hash(books)==state['hash'],'Копия Books повреждена.')
    desired = None
    async with AfcService(device) as afc:
        if record.get('complete'):
            # The carrier stage finished; only the Books cleanup failed. Never roll back the catalog.
            if (other:=await restore_books(afc,books,state['existed'],state.get('top'))):record['books_other_changes']=other[:50]
            record['recovered_by']=str(run);record['books_restored']=True
            save_json(failed/'journal.json',record)
            return
        if record.get('phase') in ('host-started','export-check') and not await exists(afc,remote):
            # The export asset may already be sent: the host sends it before the pause, and
            # FileComplete is asynchronous. Give atc time to finish the move before deciding
            # that the catalog never left its place.
            for _ in range(EXPORT_SETTLE_SECONDS):
                if await exists(afc,remote): break
                await asyncio.sleep(1)
            else:
                record['export_absent_after_wait']=EXPORT_SETTLE_SECONDS
        if await exists(afc,remote):
            desired = await remote_tree(afc,remote)
            if record.get('original_hash'):
                require(tree_hash(desired)==record['original_hash'],'Удалённая копия изменилась.')
        elif (failed/'original.zip').exists():
            desired = read_tree_zip(failed/'original.zip')
            require(tree_hash(desired)==record.get('original_hash'),'Локальная копия повреждена.')
        else:
            # No exported copy on the phone (waited for above) and none saved locally: the catalog
            # was never moved out, and the final asset is only sent after the backup is saved.
            # Only Books and the staging folders in /var/mobile/Media changed: Books is put back
            # here, the staging folders are removed by the next run's cleanup (clean_phone).
            require(record.get('phase') in ('created','staging','host-started','export-check'),
                    'Нет проверенной копии. Сохраните runs; восстановление остановлено.')
        if (other:=await restore_books(afc,books,state['existed'],state.get('top'))):record['books_other_changes']=other[:50]
    if desired is not None:
        write_tree_zip(run/f'recovery-original{tag}.zip',desired)
        await transfer(device,run/f'recover{tag}',payload=desired,recovery=True)
        observed=await transfer(device,run/f'readback{tag}')
        require(observed==desired,'Восстановленный каталог не совпадает с копией.')
    record['recovered_by']=str(run);record['requires_recovery']=False;record['books_restored']=True
    save_json(failed/'journal.json',record)


async def recover_all(device, stages, run):
    # Undo newest first: a failed recovery attempt is itself a stage on top of the one it repaired.
    for i,failed in enumerate(reversed(stages),1):
        print('Восстанавливаю этап:',failed,flush=True)
        await recover_stage(device,failed,run,f'-{i}' if len(stages)>1 else '')


def check_trigger_hardware(path, hardware, warn=True):
    tree = read_tree_zip(path)
    board = hardware.upper().removesuffix('AP')
    for name,(kind,_) in tree.items():
        leaf = name.rsplit('/',1)[-1]
        if kind!='f' or '/signatures/' in name or not leaf.startswith('overrides_') or not leaf.endswith('.plist'):
            continue
        boards = leaf.removeprefix('overrides_').removesuffix('.plist').upper().split('_')
        if board in boards:
            signature = name.rsplit('/',1)[0]+'/signatures/'+leaf
            if signature in tree:
                return True
            break
    if warn:
        print('Предупреждение: в IPCC нет настроек с подписью для платы '+hardware+
              '. Пересканирование МОЖЕТ не работать; продолжаю.', flush=True)
    return False



# Read-only telephony diagnostics from the CommCenter log stream (os_trace_relay).
# Note: patterns come from iOS 27.x CommCenter strings seen in rescan logs; Apple
# does not document them, so a future iOS may rename them. Raw masked log is saved
# next to the report so the patterns can be updated.
DIAG_PATTERNS = {
    'ims_voice': re.compile(r'IMS Voice registered: (true|false)'),
    'ims_over_wifi': re.compile(r'IMS registered\s*:\s*(true|false)\s*,\s*Over Wifi\s*:\s*(true|false)'),
    'vowifi_pref': re.compile(r'VoWiFi, user preference status is (\w+).*?service status: (\w+)'),
    'vowifi_config': re.compile(r'VoWiFi configuration is: (\w+) \(preferred in roaming: (\w+)\)'),
    'features': re.compile(r'VoLTE Feature support: (\w+), VoNR Feature support: (\w+), VoWiFi Feature support: (\w+)'),
    'roaming': re.compile(r'Is device roaming: (kRoaming|kNotRoaming)\b'),
    'reg_status': re.compile(r'Registration status is (k\w+)'),
    'rat': re.compile(r'(?:current RAT \(|RAT remains at |current RAT set to )(kRat\w+)'),
    'data_mode': re.compile(r'(?:current DataMode set to |Data mode - )(k\w+)'),
    'plmn': re.compile(r'(kRat\w+) PLMN: (\d{3}-\d{2,3})'),
    'signal': re.compile(r'Rsrp=\{y=(-?[\d.]+) : \d+\}, Sinr=\{y=(-?[\d.]+)'),
    'wifi_name': re.compile(r"Operator name is being overridden to '([^']+)'"),
    'sa': re.compile(r'5G Standalone (enabled|disabled)(?: by (\w+))?'),
    'ims_reg': re.compile(r'UE is Registered for ([\w+]+) on (\w+)'),
    'call_status': re.compile(r'slot k\w+ call status (\w+)'),
}
# P-Access-Network-Info in SIP says which radio carried the call.
SIP_ACCESS = {'IEEE-802.11':'Wi-Fi (VoWiFi)','3GPP-E-UTRAN':'LTE (VoLTE)','3GPP-E-UTRAN-FDD':'LTE (VoLTE)',
              '3GPP-E-UTRAN-TDD':'LTE (VoLTE)','3GPP-NR':'5G (VoNR)','3GPP-NR-FDD':'5G (VoNR)',
              '3GPP-NR-TDD':'5G (VoNR)','3GPP-UTRAN-FDD':'3G'}


CODEC_NAMES = {'EVS/16000':'EVS (HD Voice+)','AMR-WB/16000':'AMR-WB (HD Voice)',
               'AMR/8000':'AMR-NB (обычное качество)','PCMA/8000':'G.711 A-law (обычное качество)',
               'PCMU/8000':'G.711 µ-law (обычное качество)'}


def sip_answer_codec(message):
    # An SDP answer lists exactly one voice codec (plus telephone-event); offers list several.
    m = re.search(r'^\s*m=audio \d+ RTP/AVP ([\d ]+)', message, re.M)
    if not m:
        return None
    maps = dict(re.findall(r'a=rtpmap:(\d+) ([\w.-]+/\d+)', message))
    voice = [maps[p] for p in m.group(1).split() if p in maps and not maps[p].startswith('telephone-event')]
    return voice[0] if len(voice) == 1 else None


def mask_log(text):
    # Phone numbers, IMSI/ICCID and other long identifiers never reach disk or screen.
    return re.sub(r'\+?\d[\d ()-]{6,}\d', '<num>', text)


def log_slot(entry):
    # CommCenter prefixes per-subscription lines with "<slot>.<n> "; categories may end in the slot.
    # Heuristic, unverified on every iOS; unmatched lines are reported as "общее".
    if m := re.match(r'([12])\.\d+\s', entry.message):
        return {'1':'kOne','2':'kTwo'}[m.group(1)]
    if m := re.search(r'\bslot (kOne|kTwo)\b', entry.message):
        return m.group(1)
    # Categories end in ".<slot>" (reg.ctr.2, sig.mav5.1) or ".<slot>.<n>" (sip.dump.ims.1.4).
    if entry.label and (m := re.search(r'\.([12])(?:\.\d+)?$', entry.label.category or '')):
        return {'1':'kOne','2':'kTwo'}[m.group(1)]
    return None


def sip_assembler():
    # CommCenter logs each SIP line as its own entry in category sip.dump.*:
    # "==== src --> dst METHOD ====", the message lines, then a "=====" rule.
    # Returns feed(entry) -> (first SIP line, access network, answered codec) once a message completes.
    bufs = {}
    def feed(entry):
        cat = entry.label.category if entry.label else ''
        if not (cat or '').startswith('sip.dump'):
            return None
        line = entry.message.strip()
        if re.fullmatch(r'=+', line):
            if cat not in bufs:
                return None
            msg = '\n'.join(bufs.pop(cat))
            cseq = re.search(r'^CSeq: \d+ (\w+)', msg, re.M)
            if not cseq or cseq.group(1) not in ('INVITE', 'PRACK', 'UPDATE', 'ACK', 'BYE', 'CANCEL'):
                return None  # registration, presence and SMS traffic is not a call
            first = next((l for l in msg.splitlines() if l.strip()), '')
            first = re.sub(r'^(\w+) \S+ SIP/2\.0$', r'\1', first)  # drop request URI (holds the number)
            access = re.search(r'P-Access-Network-Info: ([\w.-]+)', msg)
            return first, access and SIP_ACCESS.get(access.group(1), access.group(1)), sip_answer_codec(msg)
        elif line.startswith('='):
            bufs[cat] = []  # "==== src --> dst ... ====" header, either direction
        elif cat in bufs:
            bufs[cat].append(line)
        return None
    return feed


async def commcenter_stream(device, seconds, log_path, on_entry):
    from pymobiledevice3.services.os_trace import OsTraceService
    pids = (await OsTraceService(device).get_pid_list()).get('Payload', {})
    pid = next((int(p) for p, v in pids.items() if v.get('ProcessName') == 'CommCenter'), None)
    require(pid is not None, 'Процесс CommCenter не найден на iPhone.')
    with log_path.open('w', encoding='utf-8') as f:
        try:
            async with asyncio.timeout(seconds):
                async for e in OsTraceService(device).syslog(pid=pid):
                    msg = mask_log(e.message)
                    cat = f'{e.label.subsystem}:{e.label.category}' if e.label else '-'
                    f.write(f'{e.timestamp:%H:%M:%S} [{cat}] {msg}\n')
                    on_entry(e, msg)
        except TimeoutError:
            pass


def diag_collect(state):
    feed_sip = sip_assembler()
    def on_entry(e, msg):
        # Returns the completed SIP message summary, if this entry finished one.
        slot = log_slot(e) or 'общее'
        for key, pat in DIAG_PATTERNS.items():
            if m := pat.search(msg):
                state.setdefault(slot, {})[key] = m.groups()
        if sip := feed_sip(e):
            _, access, codec = sip
            if access:
                state.setdefault(slot, {})['call_access'] = (access,)
            if codec:
                state.setdefault(slot, {})['codec'] = (codec,)
        return sip
    return on_entry


def sim_header(row):
    return f"{SLOT_NAMES[row['Slot']]}  ·  {row.get('MCC', '')}{row.get('MNC', '')}"


def diag_report(state, rows):
    yes = lambda v: {'true':'да','false':'нет','kTrue':'да','kFalse':'нет'}.get(v, v)
    rat = lambda v: v and {'kRatGSM':'2G (GSM)','kRatUMTS':'3G (UMTS)','kRatLTE':'4G (LTE)','kRatNR':'5G (NR)'}.get(v, v)
    reg = lambda v: v and {'kRegisteredHome':'в домашней сети','kRegisteredRoaming':'в роуминге',
                           'kNotRegistered':'нет регистрации','kRegistrationDenied':'отказ сети',
                           'kSearching':'поиск сети'}.get(v, v)
    lines = []
    for slot in [r.get('Slot') for r in rows if r.get('Slot') in ('kOne','kTwo')] + ['общее']:
        s = state.get(slot, {})
        if slot == 'общее' and not s:
            continue
        head = sim_header(next(r for r in rows if r.get('Slot') == slot)) \
            if slot != 'общее' else 'Без привязки к SIM (слот не определён по журналу)'
        lines.append('\n  ' + head)
        g = lambda k, i=0: s[k][i] if k in s and s[k][i] else None
        items = [
            ('IMS', g('ims_reg') and f"{g('ims_reg')} через {g('ims_reg',1)}"),
            ('IMS (голос)', yes(g('ims_voice'))),
            ('IMS через Wi-Fi', g('ims_over_wifi') and f"регистрация: {yes(g('ims_over_wifi'))}, Wi-Fi: {yes(g('ims_over_wifi',1))}"),
            ('VoWiFi', g('vowifi_pref') and f"настройка: {g('vowifi_pref')}, служба: {g('vowifi_pref',1)}"),
            ('VoWiFi из', g('vowifi_config') and f"{g('vowifi_config')}, предпочтителен в роуминге: {yes(g('vowifi_config',1))}"),
            ('Поддержка', g('features') and f"VoLTE {yes(g('features'))}, VoNR {yes(g('features',1))}, VoWiFi {yes(g('features',2))}"),
            ('Wi-Fi Calling имя', g('wifi_name') and f"«{g('wifi_name')}» (VoWiFi активен)"),
            ('Регистрация', reg(g('reg_status'))),
            ('Роуминг', g('roaming') and {'kRoaming':'да','kNotRoaming':'нет'}.get(g('roaming'), g('roaming'))),
            ('Сеть', rat(g('rat'))),
            ('Данные', g('data_mode') and g('data_mode').removeprefix('k')),
            ('Обслуживающая сеть', g('plmn') and f"{g('plmn',1)} ({rat(g('plmn'))})"),
            ('Сигнал LTE', g('signal') and f"RSRP {float(g('signal')):.0f} дБм, SINR {float(g('signal',1)):.1f} дБ"),
            ('5G SA', g('sa') and (g('sa') == 'enabled' and 'включён' or f"выключен ({g('sa',1) or 'причина не указана'})")),
            ('Звонок через', g('call_access')),
            ('Кодек звонка', g('codec') and CODEC_NAMES.get(g('codec'), g('codec'))),
        ]
        shown = [(name, val) for name, val in items if val]
        for name, val in shown:
            lines.append(f'    {name:20} {val}')
        if len(shown) < len(items):
            lines.append('    остальное: нет в журнале за это время')
    return '\n'.join(lines)


async def run_diagnose(device, args, rows):
    out = args.runs / (datetime.now().strftime('%Y%m%d-%H%M%S-') + 'diagnose')
    out.mkdir(parents=True, mode=0o700)
    print(f'Собираю журнал CommCenter {args.seconds} с. Чтобы iOS заново прошла регистрацию,\n'
          'включите и через 10 секунд выключите авиарежим (Wi-Fi оставьте включённым).', flush=True)
    state = {}
    await commcenter_stream(device, args.seconds, out / 'commcenter.log', diag_collect(state))
    report = diag_report(state, rows)
    print(report, flush=True)
    (out / 'report.txt').write_text(report + '\n', encoding='utf-8')
    print(f'\nСлот SIM определяется по журналу эвристически. Журнал (замаскирован): {out}', flush=True)
    return 0


async def run_watch_call(device, args, rows):
    out = args.runs / (datetime.now().strftime('%Y%m%d-%H%M%S-') + 'watch-call')
    out.mkdir(parents=True, mode=0o700)
    print(f'Слушаю журнал CommCenter {args.seconds} с. Сделайте тестовый звонок сейчас.\n'
          'Для VoWiFi: авиарежим + Wi-Fi. Для VoLTE: Wi-Fi выключен.', flush=True)
    state = {}
    collect = diag_collect(state)
    def on_entry(e, msg):
        sip = collect(e, msg)
        slot = {'kOne':'SIM 1','kTwo':'SIM 2'}.get(log_slot(e), '     ')
        if sip:
            first, access, codec = sip
            extra = ' · '.join(x for x in (access, codec and 'кодек ' + CODEC_NAMES.get(codec, codec)) if x)
            print(f'  {e.timestamp:%H:%M:%S} {slot} SIP {first}' + (f'  [{extra}]' if extra else ''), flush=True)
        elif m := DIAG_PATTERNS['call_status'].search(msg):
            print(f'  {e.timestamp:%H:%M:%S} {slot} звонок: {m.group(1)}', flush=True)
    await commcenter_stream(device, args.seconds, out / 'commcenter.log', on_entry)
    codecs = sorted({CODEC_NAMES.get(v['codec'][0], v['codec'][0]) for v in state.values() if 'codec' in v})
    print('\nСогласованные кодеки: ' + (', '.join(codecs) if codecs else 'звонков с ответом SDP не было'), flush=True)
    report = diag_report(state, rows)
    print(report, flush=True)
    (out / 'report.txt').write_text(report + '\n', encoding='utf-8')
    print(f'\nЖурнал (замаскирован): {out}', flush=True)
    return 0


async def diagnostics(args):
    device=await ready_device(args.udid,args.wait_seconds)
    try:
        info=await device_info(device); DIAG['info']=info
        rows=await device.get_value(key='CarrierBundleInfoArray') or []
        print(f"\n  {MODELS.get(info['ProductType'], {}).get('name', info['ProductType'])} · iOS {info['ProductVersion']} ({info['BuildVersion']})",flush=True)
        for r in rows:
            if r.get('Slot') in SLOT_NAMES: print('  '+sim_header(r),flush=True)
        print(flush=True)
        return await (run_diagnose if args.diagnose else run_watch_call)(device,args,rows)
    finally:await device.close()


async def execute(args,assets):
    udid=args.udid
    device=await ready_device(udid,args.wait_seconds)
    run=None
    try:
        info=await device_info(device); DIAG['info']=info; check_phone(info)
        rows=await device.get_value(key='CarrierBundleInfoArray') or []
        top=await device.get_value() or {}
        slots=SLOT_CHOICES[args.sims]
        sims=select_sims(rows,args.bundles,slots) if not (args.restore or args.restore_backup or args.recover) else []
        restore_imsis=None
        if args.restore:
            sims=[{'slot':r['Slot'],'plmn':str(r.get('MCC',''))+str(r.get('MNC','')),'bundle':None}
                  for r in rows if r.get('Slot') in slots]
            if args.sims!='all':
                # Only this SIM's alias is removed, so its IMSI must be known.
                restore_imsis={s['imsi'] for s in select_sims(rows,None,slots)}
        print(f"\n  {MODELS.get(info['ProductType'], {}).get('name', info['ProductType'])} · iOS {info['ProductVersion']} ({info['BuildVersion']})",flush=True)
        row_by_slot={r.get('Slot'):r for r in rows}
        for s in sims:
            target='штатный профиль' if args.restore else s['bundle'].removesuffix('.bundle')+' (по IMSI)'
            print(f"  {sim_line(row_by_slot[s['slot']],top)}  →  план: {target}",flush=True)
        print(flush=True)
        if args.status:
            print('Сверьте последние 4 цифры ICCID: Настройки → Основные → Об этом устройстве → ICCID нужной линии. '
                  '«сейчас» — профиль, загруженный iPhone; «план» — что будет записано.',flush=True)
            return
        custom=None
        if args.trigger:
            # Checked before any run folder or phone change; the copy below must be this same file.
            custom=check_trigger(args.trigger,{str(r.get('MCC',''))+str(r.get('MNC','')) for r in rows},{s['bundle'] for s in sims if s['bundle']})
            check_trigger_hardware(args.trigger,info['HardwareModel'])
        unresolved=pending(args.runs,udid)
        # Recomputed on every attempt: a failed attempt's auto-recovery may already have fixed some stages.
        recover=args.recover
        if recover == Path('AUTO'):
            if not unresolved:
                print('Незавершённых операций для этого iPhone нет, восстанавливать нечего.');return 0
            recover=unresolved
        require(not unresolved or recover,
                'Прошлая операция на этом iPhone не завершилась. Сначала '+recover_hint()+
                ', затем повторите действие. Этап: '+str(unresolved[0] if unresolved else ''))
        run=args.runs/(datetime.now().strftime('%Y%m%d-%H%M%S-')+uuid.uuid4().hex[:6])
        run.mkdir(mode=0o700); DIAG['run']=run; save_environment(run)
        print('Копии и журнал:',run,flush=True)
        print('Идёт установка или восстановление, ожидайте… Не отключайте iPhone.',flush=True)
        save_json(run/'device.json',{**info,'udid_hash':digest(udid.encode())})
        trigger=None
        plmns={str(r.get('MCC',''))+str(r.get('MNC','')) for r in rows}
        # Prefer a trigger with signed overrides for this board; otherwise the first one that fits the SIMs.
        fitting=[]
        for name in (() if args.trigger or assets is None else ('AVEA_tr.ipcc','Swisscom_ch.ipcc','O2_Germany.ipcc')):
            candidate=run/name;candidate.write_bytes(assets['triggers/'+name][1])
            try:
                check_trigger(candidate,plmns,{s['bundle'] for s in sims if s['bundle']})
            except RuntimeError:candidate.unlink();continue
            if check_trigger_hardware(candidate,info['HardwareModel'],warn=False):
                trigger=candidate;break
            fitting.append(candidate)
        if trigger is None and fitting:
            trigger=fitting[0];check_trigger_hardware(trigger,info['HardwareModel'])
        for extra in fitting:
            if extra!=trigger:extra.unlink()
        if args.trigger:
            trigger=run/'custom-trigger.ipcc';trigger.write_bytes(args.trigger.read_bytes())
            require(digest(trigger.read_bytes())==custom['sha256'],'Файл IPCC изменился после проверки.')
        # Recovery itself needs no trigger: it is only for the rescan at the end.
        require(trigger is not None or recover,'Не найден независимый триггер для этих SIM.')
        if trigger is not None: DIAG['trigger']=trigger.name
        if not args.recover:
            # No unfinished stage is known here (checked above), so AirLift leftovers are stale.
            cleaned=await clean_phone(device,run)
            kept=[n for n,v in cleaned.items() if str(v).startswith('не удалён')]
            removed=[n for n in cleaned if n not in kept]
            if removed:print('Убраны остатки прошлых запусков: '+', '.join(removed),flush=True)
            if kept:print('Не удалось убрать остатки прошлых запусков: '+', '.join(kept),flush=True)
        if recover:
            if isinstance(recover,list):await recover_all(device,recover,run)
            else:await recover_stage(device,recover.resolve(),run)
        elif args.restore:
            print('[1/4] Подготавливаю пересканирование…',flush=True)
            init=run/'initialize';init.mkdir();await install_trigger(device,trigger,init)
            print('[2/4] Сохраняю текущие настройки…',flush=True)
            original=await transfer(device,run/'snapshot')
            if restore_imsis is not None:
                now={s['imsi'] for s in select_sims(await device.get_value(key='CarrierBundleInfoArray') or [],None,slots)}
                require(now==restore_imsis,'SIM изменились во время операции; запись отменена.')
            desired=remove_imsi_links(original,restore_imsis)
            removed=len(original)-len(desired)
            save_json(run/'plan.json',{'action':'remove-imsi','sims':args.sims,'removed':removed,
                                      'before':tree_hash(original),'after':tree_hash(desired)})
            if not removed:
                print('[3/4] Ссылок по IMSI для выбранных SIM нет: они уже на штатном профиле. Ничего не меняю.',flush=True)
                return 0
            print(f'[3/4] Удаляю ссылки по IMSI: {removed}. Проверяю результат…',flush=True)
            await transfer(device,run/'restore',payload=desired,expected=original)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        elif args.restore_backup:
            failed=args.restore_backup.resolve()/'snapshot'
            record=read_json(failed/'journal.json');bound(record,device)
            desired=read_tree_zip(failed/'original.zip')
            require(tree_hash(desired)==record.get('original_hash'),'Копия повреждена.')
            await transfer(device,run/'restore',payload=desired,recovery=True)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        else:
            # A non-overlapping trigger also creates the user catalog on a clean phone.
            init=run/'initialize';init.mkdir()
            print('[1/4] Подготавливаю пересканирование…',flush=True)
            await install_trigger(device,trigger,init)
            print('[2/4] Сохраняю исходные настройки…',flush=True)
            original=await transfer(device,run/'snapshot')
            require(original is not None,'Не удалось сохранить исходный каталог.')
            current=select_sims(await device.get_value(key='CarrierBundleInfoArray') or [],args.bundles,slots)
            require(current==sims,'SIM изменились во время операции; запись отменена.')
            desired=make_plan(original,sims)
            save_json(run/'plan.json',{'slots':[{k:v for k,v in s.items() if k!='imsi'} for s in sims],
                                      'before':tree_hash(original),'after':tree_hash(desired)})
            print('[3/4] Записываю ссылки по IMSI и проверяю результат…',flush=True)
            await transfer(device,run/'apply',payload=desired,expected=original)
            require(await transfer(device,run/'readback')==desired,'Обратное чтение не совпало.')
        if trigger is None:
            print('Каталог восстановлен. Пересканирование пропущено: нет подходящего триггера '
                  'или assets.zip недоступен. Если связь не вернулась, перезагрузите iPhone.',flush=True)
            return 0
        print('[4/4] Ожидаю применения профиля и проверки подписей…',flush=True)
        rescan=run/'rescan';rescan.mkdir()
        installation=await install_trigger(device,trigger,rescan)
        result=report_log(rescan/'commcenter.log',sims)
        save_json(run/'result.json',{'catalog_verified':True,'installation':installation,'slots':result})
        unconfirmed=False
        for s in result:
            ok=s['verified'] and (args.restore or (s['selected'] or '').lower()==s['expected'].lower());unconfirmed |= not ok
            print(f"{SLOT_NAMES[s['slot']]} ({s['plmn']}): "+(s['selected']+' — подпись принята' if ok else
                  'выбор нужного пакета не подтверждён; см. журнал'),flush=True)
        if args.restore:
            print(('Ссылка по IMSI выбранной SIM удалена, другая SIM не тронута.' if restore_imsis else
                   'Все ссылки по IMSI удалены.')+' Обычные ссылки операторов сохранены.',flush=True)
        installing=not (args.restore or args.restore_backup or args.recover)
        missing=[]
        if installing:
            # Roll back only on evidence: iOS chose another bundle, or CommCenter logged its bundle
            # choice but not ours. A missing or broken log proves nothing and stays "unconfirmed".
            log=rescan/'commcenter.log'
            log_ok=(not (installation or {}).get('log_error') and log.exists()
                    and BUNDLE_BLOCK in log.read_text(encoding='utf-8',errors='replace'))
            missing=sorted({s['expected'] for s in result if s['expected']
                            and (s['selected'] or log_ok)
                            and (s['selected'] or '').lower()!=s['expected'].lower()})
        if missing:
            # AFC cannot read /System, so a missing bundle only shows up in the rescan log.
            # Never leave links to it: put back the catalog saved before this write.
            print('iOS не выбрала '+', '.join(missing)+': такого пакета, видимо, нет в этой '
                  'версии iOS или имя введено с ошибкой. Возвращаю прежние настройки…',flush=True)
            # The rescan trigger may have touched other parts of the catalog since the readback;
            # only this run's IMSI links must still be exactly as written.
            await transfer(device,run/'rollback',payload=original,
                           expected=lambda tree:imsi_links(tree)==imsi_links(desired))
            require(await transfer(device,run/'rollback-readback')==original,
                    'Прежние настройки не вернулись: '+recover_hint()+'.')
            rescan=run/'rescan-rollback';rescan.mkdir()
            await install_trigger(device,trigger,rescan)
            save_json(run/'result.json',{'catalog_verified':True,'installation':installation,'slots':result,
                                         'rolled_back':True})
            print('Прежние настройки возвращены. Проверьте имя пакета (bundle.yaml или пункт 7) и повторите.',flush=True)
            return UNCONFIRMED
        if unconfirmed:return UNCONFIRMED
        print('Books: служебные файлы синхронизации возвращены в исходное состояние'+books_summary(run)+'.',flush=True)
        print('Готово. Включите авиарежим на 15 секунд и проверьте связь. Работа 5G не проверялась.')
        return 0
    except BaseException as error:
        if run:
            save_json(run/'error.json',{'error':type(error).__name__+': '+str(error)})
            # execute_with_retry rolls back any unfinished stage and reports the outcome.
            print('Операция остановлена. Журнал:',run,file=sys.stderr)
        raise
    finally:await device.close()

# ---- Diagnostics printed on failure: enough to debug without sending the runs folder.
# Never includes IMSI, UDID or serial numbers.
DIAG = {}


def win_file_version(path):
    try:
        v = C.windll.version
        size = v.GetFileVersionInfoSizeW(str(path), None)
        if not size: return None
        buf = C.create_string_buffer(size)
        if not v.GetFileVersionInfoW(str(path), 0, size, buf): return None
        ptr, length = C.c_void_p(), C.c_uint()
        if not v.VerQueryValueW(buf, '\\', C.byref(ptr), C.byref(length)): return None
        info = C.cast(ptr, C.POINTER(C.c_uint32 * 13)).contents
        ms, ls = info[2], info[3]
        return f'{ms >> 16}.{ms & 0xffff}.{ls >> 16}.{ls & 0xffff}'
    except Exception:
        return None


def sysctl(name):
    try:
        return subprocess.run(['/usr/sbin/sysctl', '-n', name], capture_output=True, text=True, timeout=5).stdout.strip() or None
    except Exception:
        return None


def environment_info():
    import platform
    from importlib.metadata import version, metadata, PackageNotFoundError
    rows = [('Сборка скрипта', digest((ROOT/'carrier.py').read_bytes())[:12]),
            ('Python', f"{sys.version.split()[0]} {platform.machine()} {'64' if sys.maxsize > 2**32 else '32'}-bit")]
    libs = []
    for name in ('pymobiledevice3', 'cryptography', 'pyimg4', 'pylzss', 'lzfse'):
        try:
            placeholder = 'placeholder' in (metadata(name).get('Summary') or '')
            libs.append(f"{name} {version(name)}{' (заглушка)' if placeholder else ''}")
        except PackageNotFoundError:
            libs.append(f'{name} нет')
    rows.append(('Библиотеки', ', '.join(libs)))
    if sys.platform == 'darwin':
        cpu = 'Apple Silicon' if sysctl('hw.optional.arm64') == '1' else 'Intel'
        if sysctl('sysctl.proc_translated') == '1': cpu += ', Python под Rosetta'
        rows.append(('macOS', f"{platform.mac_ver()[0]} · {sysctl('hw.model') or '?'} · {cpu} · {sysctl('machdep.cpu.brand_string') or ''}".rstrip(' ·')))
        try:
            at = plistlib.loads(Path('/System/Library/PrivateFrameworks/AirTrafficHost.framework/Resources/Info.plist').read_bytes())
            rows.append(('AirTrafficHost', f"{at.get('CFBundleShortVersionString')} ({at.get('CFBundleVersion')})"))
        except Exception:
            rows.append(('AirTrafficHost', 'версия не прочитана'))
    elif sys.platform == 'win32':
        w = sys.getwindowsversion()
        rows.append(('Windows', f"{platform.release()} {platform.version()} (build {w.build}) · {platform.machine()}"))
        source, _ = windows_apple_cohesive_dir(APPLE_DIRS)
        cache = APPLE_DLL_CACHE
        cache_ok = all((cache/n).is_file() for n in ('CoreFoundation.dll', 'AirTrafficHost.dll'))
        rows.append(('Apple DLL источник', str(source) if source else 'не найден (нужны CF+AT в одной папке)'))
        rows.append(('.apple-dlls', f'используется ({cache})' if cache_ok else 'нет'))
        # Versions from effective load paths: cache when present (ACL fallback), else cohesive source.
        eff = cache if cache_ok else source
        for name in ('AirTrafficHost.dll', 'MobileDevice.dll', 'CoreFoundation.dll'):
            p = (eff/name) if eff and (eff/name).is_file() else None
            if p is None and source and (source/name).is_file():
                p = source/name
            rows.append((name, f'{win_file_version(p) or "?"} ({p.parent})' if p else 'не найдена'))
        if source and 'appleinc.appledevices_' in str(source).lower():
            rows.append(('Apple Devices', f'найден ({source})'))
        elif source and 'mobile device support' in str(source).lower():
            rows.append(('Apple Mobile Device Support', f'найден ({source})'))
        elif source:
            rows.append(('Apple DLL папка', str(source)))
        else:
            rows.append(('Apple Devices / AMDS', 'не найдены (нужны DLL AirTrafficHost и CoreFoundation в одной папке)'))
        itunes = [Path(os.environ[k])/'iTunes'/'iTunes.exe' for k in ('ProgramW6432', 'ProgramFiles') if os.environ.get(k)]
        itunes = next((x for x in itunes if x.is_file()), None)
        rows.append(('iTunes.exe', ((win_file_version(itunes) or '?') + ' (не требуется)' if itunes else 'нет (не требуется)')))
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Services\Apple Mobile Device Service') as svc:
                start, _ = winreg.QueryValueEx(svc, 'Start')
            state = {2: 'автозапуск', 3: 'вручную', 4: 'отключена'}.get(start, f'Start={start}')
            rows.append(('Apple Mobile Device Service', 'установлена · ' + state))
        except Exception:
            rows.append(('Apple Mobile Device Service', 'не найдена'))
        try:
            drv = Path(os.environ.get('SystemRoot', r'C:\Windows'))/'System32'/'drivers'/'usbaapl64.sys'
            rows.append(('Apple Mobile Device USB', 'usbaapl64.sys есть' if drv.is_file() else 'usbaapl64.sys не найден (см. README)'))
        except Exception:
            rows.append(('Apple Mobile Device USB', 'не проверен'))
    else:
        rows.append(('ОС', platform.platform()))
    return rows



def outstanding_assets(tree):
    # Read Books/Sync/Database/OutstandingAssets_4.sqlite (with its WAL) from a Books backup.
    import sqlite3
    base = OUTSTANDING_DB.removeprefix('Books/')
    if base not in tree: return None
    try:
        return read_outstanding({suffix: tree[base + suffix][1] for suffix in ('', '-wal', '-shm') if base + suffix in tree})
    except sqlite3.Error:
        return None


def books_summary(run):
    changes = sorted({c for j in run.glob('*/journal.json') for c in read_json(j).get('books_other_changes', [])})
    return ('; за время установки в корне Books изменилось: ' + ', '.join(changes[:10])) if changes else ''


def run_details(run):
    rows = []
    for journal in sorted(run.glob('*/journal.json'), key=lambda p: p.stat().st_mtime):
        stage = journal.parent
        try: j = read_json(journal)
        except Exception: continue
        line = f"фаза {j.get('phase')}, завершён {bool(j.get('complete'))}, Books восстановлен {j.get('books_restored')}"
        if j.get('stale_books_removed'): line += f", удалены старые записи: {j['stale_books_removed']}"
        if j.get('books_other_changes'): line += f", iOS изменила в Books: {', '.join(j['books_other_changes'][:8])}"
        if j.get('media_leftovers'):
            old = sorted({n.rsplit('-', 1)[-1] for n in j['media_leftovers']} - {str(j.get('source', '')).rsplit('-', 1)[-1]})
            rows.append(('  Остатки прошлых запусков в Media', ', '.join(j['media_leftovers'][:12]) + (f' (запусков: {len(old)})' if old else '')))
        if j.get('operation_error'): line += f", ошибка: {j['operation_error']}"
        rows.append((f'Этап {stage.name}', line))
        try:
            b = read_json(stage/'books.json'); tree = read_tree_zip(stage/'books.zip')
            known = [n for n in (x.removeprefix('Books/') for x in BOOK_FILES + BOOK_DIRS[1:]) if n in tree]
            rows.append(('  Books до операции', f"{'был' if b.get('existed') else 'не было'}, служебные: {', '.join(known) or 'нет'}"
                         + (f", в корне: {', '.join(b['top'][:15])}" if b.get('top') else '')))
            outstanding = outstanding_assets(tree)
            if outstanding is not None:
                mine = [x for x in outstanding if our_trace(x[0])]
                rows.append(('  Незавершённые загрузки Books', f'{len(outstanding)}, из них скрипта {len(mine)}'))
                for pid, done in mine[:6]:
                    rows.append(('    загрузка', f'{pid} → {done or "не завершена"}'))
            traces = sorted(n for n, (k, d) in tree.items() if k == 'f' and b'airlift' in d)
            if traces: rows.append(('  Следы airlift в Books', ', '.join(traces)))
        except Exception:
            pass
        host = stage/'host.jsonl'
        if host.exists():
            names = []
            for raw in host.read_text(encoding='utf-8', errors='replace').splitlines():
                if not raw.startswith('CARRIER_SWAP_JSON:'): continue
                try: row = json.loads(raw.split(':', 1)[1])
                except ValueError: continue
                if row.get('event') == 'manifest':
                    book = row.get('book', [])
                    expected = set(row.get('expected', []))
                    rows.append(('  Ответ AirTraffic', f"типы {row.get('dataclasses')}, объектов Book {len(book)}, "
                                 f"IsDownload {sum(1 for x in book if x.get('IsDownload') in ('True', '1'))}, "
                                 f"наших {sum(1 for x in book if x.get('AssetID') in expected)} из {len(expected)}"))
                    for x in book[:5]:
                        rows.append(('    Book', ', '.join(f'{k}={v[:60]}' for k, v in x.items())))
                elif row.get('ok') is False:
                    rows.append(('  Ошибка AirTraffic', str(row.get('error'))))
                elif row.get('event') == 'message':
                    names.append(row.get('name'))
            if names: rows.append(('  Сообщения AirTraffic', ' → '.join(map(str, names))))
        dlog = stage/'device.log'
        if dlog.exists():
            lines = dlog.read_text(encoding='utf-8', errors='replace').splitlines()
            # Only AirTraffic, Books and sandbox problems; trustd/wifid/atc(Apps) noise is in device.log.
            source = re.compile(r'\batc\((AirTraffic\w*|ATFoundation|Books|Foundation)\)|kernel\(Sandbox\)')
            problem = re.compile(r'<Error>|<Fault>|\bdeny\(|Aborting|SyncFailed|ErrorCode|installOnly=1|'
                                 r'could not|not found|no such file', re.I)
            # Present in every successful run as well: not a cause.
            benign = ('ATGetUsageForPath', 'Artwork file does not exist', 'ATStoreInfo with no',
                      "Asset path isn't in one of the expected directories", 'Could not create sandbox extension')
            key = [l for l in lines if source.search(l) and problem.search(l) and not any(b in l for b in benign)]
            rows.append(('  Журнал iPhone', f'{len(lines)} строк, важных {len(key)}'))
            for l in key[-12:]:
                rows.append(('    iPhone', re.sub(r'^\w{3} +\d+ [\d:]+ \S+ ', '', l.strip())[:300]))
        err = stage/'host.stderr'
        if err.exists():
            tail = [l.strip()[:200] for l in err.read_text(encoding='utf-8', errors='replace').splitlines() if l.strip()][-5:]
            for l in tail: rows.append(('  host.stderr', l))
    for name in ('initialize', 'rescan'):
        f = run/name/'installation.json'
        if f.exists():
            try:
                j = read_json(f)
                rows.append((f'Триггер ({name})', f"установлен {j.get('ipcc_installation_completed')}"
                             + (f", ошибка: {j['installation_error']}" if j.get('installation_error') else '')
                             + (f", журнал: {j['log_error']}" if j.get('log_error') else '')))
            except Exception:
                pass
    return rows



class Tee:
    # Mirrors the console into the session log so a runs folder carries everything shown.
    def __init__(self, stream, log):
        self.stream, self.log = stream, log
    def write(self, data):
        self.stream.write(data)
        with contextlib.suppress(Exception): self.log.write(data); self.log.flush()
        return len(data)
    def flush(self):
        self.stream.flush()
    def __getattr__(self, name):
        return getattr(self.stream, name)


def start_session_log(runs):
    path = runs / (datetime.now().strftime('%Y%m%d-%H%M%S-') + 'session.log')
    log = path.open('a', encoding='utf-8', buffering=1)
    log.write(' '.join(['carrier.py'] + sys.argv[1:]) + '\n')
    sys.stdout, sys.stderr = Tee(sys.stdout, log), Tee(sys.stderr, log)
    DIAG['session_log'] = str(path)


def save_environment(run):
    with contextlib.suppress(Exception):
        save_json(run / 'environment.json', dict(environment_info()))


def print_diagnostics(error):
    rows = []
    try: rows += environment_info()
    except Exception as e: rows.append(('Окружение', f'не собрано: {e}'))
    info = DIAG.get('info')
    if info:
        rows.append(('iPhone', f"{MODELS.get(info['ProductType'], {}).get('name', '?')} · {info['ProductType']} · "
                     f"{info['HardwareModel']} · iOS {info['ProductVersion']} ({info['BuildVersion']}) · {info['ActivationState']}"))
        for c in info.get('carriers', []):
            rows.append(('  SIM', f"{c.get('Slot')} {c.get('MCC','')}{c.get('MNC','')} {c.get('CFBundleIdentifier','')} {c.get('CFBundleVersion','')}"))
    args = DIAG.get('args')
    if args is not None:
        rows.append(('Действие', ' '.join(a for a in sys.argv[1:]) or 'установка'))
        rows.append(('Профиль', f"{getattr(args, 'bundles', None) or getattr(args, 'bundle', None)}, SIM: {getattr(args, 'sims', 'all')}"))
    if DIAG.get('trigger'): rows.append(('Триггер', DIAG['trigger']))
    if DIAG.get('cleanup'): rows.append(('Очистка телефона', json.dumps(DIAG['cleanup'], ensure_ascii=False)[:600]))
    run = DIAG.get('run')
    if run:
        rows.append(('Папка операции', str(run)))
        try: rows += run_details(run)
        except Exception as e: rows.append(('Журналы', f'не прочитаны: {e}'))
    rows.append(('Ошибка', f'{type(error).__name__}: {error}'))
    import traceback
    frames = [f for f in traceback.extract_tb(error.__traceback__) if f.filename.endswith(('carrier.py', 'launch.py'))]
    if frames:
        rows.append(('Где', ' → '.join(f'{f.name}:{f.lineno}' for f in frames[-4:])))
    if DIAG.get('session_log'): rows.append(('Журнал сеанса', DIAG['session_log']))
    text = '\n'.join(f'{k}: {v}' for k, v in rows)
    print('\n===== Данные для отладки: скопируйте этот блок автору =====', file=sys.stderr)
    print(text, file=sys.stderr)
    print('===== конец блока =====\n', file=sys.stderr, flush=True)
    if run:
        with contextlib.suppress(Exception):
            (run / 'diagnostics.txt').write_text(text + '\n\n' + ''.join(traceback.format_exception(error)), encoding='utf-8')



def main():
    if len(sys.argv)>1 and sys.argv[1]=='--_host':
        try:
            value=json.loads(sys.stdin.readline()) if sys.argv[2]=='check' else read_json(Path(sys.argv[2]))
            native_host(value.get('udid'),value.get('assets',[]),value.get('directories',[]))
            return 0
        except Exception as e:framed({'ok':False,'error':str(e)});return 1
    print('Исследование, разработка и тесты — Vladimir B / vlw (vlwwwwww@gmail.com).',flush=True)
    parser=argparse.ArgumentParser(description='Vodafone_hu для всех SIM независимо от страны. '
        'Без флагов: установить по IMSI на SIM, сообщённые iPhone. Без ограничений по модели iPhone и версии iOS; совместимость не гарантируется.',
        add_help=False)
    parser.add_argument('-h','--help',action='help',help='показать эту справку')
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--check',action='store_true',help='проверить файлы и библиотеки Apple, без подключения к телефону')
    group.add_argument('--status',action='store_true',help='показать найденные SIM и план, ничего не записывать')
    group.add_argument('--restore',action='store_true',help='удалить ссылки по IMSI и включить штатный выбор профилей; с --sims 1 или 2 только для этой SIM')
    group.add_argument('--restore-backup',type=Path,metavar='КАТАЛОГ',help='дополнительно: вернуть каталог из конкретной резервной копии')
    group.add_argument('--recover',type=Path,nargs='?',const=Path('AUTO'),metavar='ЭТАП',help='восстановиться после сбоя автоматически; путь к этапу необязателен')
    group.add_argument('--diagnose',action='store_true',help='отчёт по SIM: IMS, VoLTE/VoWiFi/VoNR, роуминг, сеть, 5G SA; только чтение журнала')
    group.add_argument('--watch-call',action='store_true',help='слушать журнал во время тестового звонка: кодек (EVS/AMR), канал; только чтение')
    parser.add_argument('--bundle',metavar='ПАКЕТ',
                        help='один системный пакет для всех выбранных SIM вместо bundle.yaml, например O2_Germany')
    parser.add_argument('--sims',choices=SLOT_CHOICES,default='all',
                        help='какие SIM менять (установка и --restore): 1, 2 или all — все найденные (по умолчанию)')
    parser.add_argument('--trigger',type=Path,metavar='IPCC',help='свой подписанный IPCC вместо комплектного; плата и SIM проверяются')
    parser.add_argument('--attempts',type=int,default=3,metavar='N',help='попытки при временном сбое связи (по умолчанию 3)')
    parser.add_argument('--seconds',type=int,metavar='СЕК',help='длительность --diagnose (по умолчанию 90) или --watch-call (по умолчанию 180)')
    parser.add_argument('--wait-seconds',type=int,default=180,metavar='СЕК',help='ожидать подключение и разблокировку (по умолчанию 180 секунд)')
    parser.add_argument('--udid',metavar='ID',help='выбрать iPhone, если подключено несколько')
    parser.add_argument('--wifi',action='store_true',help='подключаться по Wi-Fi вместо кабеля (медленнее); нужны доверие и «Показывать iPhone при Wi-Fi», включённые заранее через кабель')
    parser.add_argument('--apple-dir',action='append',default=[],metavar='ПАПКА',help='Windows: папка DLL Apple; можно указать несколько раз')
    parser.add_argument('--runs',type=Path,default=ROOT/'runs',metavar='ПАПКА',help='куда сохранять копии и журналы (по умолчанию runs рядом со скриптом)')
    parser._optionals.title='Параметры'
    args=parser.parse_args()
    DIAG['args']=args
    if args.bundle:
        args.bundle=args.bundle.strip().removesuffix('.bundle')+'.bundle'
        require(re.fullmatch(r'[A-Za-z0-9_]+\.bundle',args.bundle),
                'Имя пакета может содержать только латинские буквы, цифры и _, например O2_Germany.')
        args.bundles={'default':args.bundle}
    else:
        args.bundles=load_bundle_config()
    require(1 <= args.attempts <= 10, 'Число попыток должно быть от 1 до 10.')
    require(0 <= args.wait_seconds <= 3600, 'Ожидание должно быть от 0 до 3600 секунд.')
    args.seconds = args.seconds or (180 if args.watch_call else 90)
    require(10 <= args.seconds <= 1800, '--seconds: от 10 до 1800.')
    os.umask(0o077)
    require(sys.version_info >= (3,11), 'Нужен Python 3.11 или новее.')
    from importlib.metadata import version, PackageNotFoundError
    try: installed=version('pymobiledevice3')
    except PackageNotFoundError: raise RuntimeError('Установите зависимости: python -m pip install -r requirements.txt') from None
    require(installed=='11.12.5', 'Нужен pymobiledevice3 11.12.5: python -m pip install -r requirements.txt')
    try: assets=load_assets()
    except Exception as error:
        # Recovery must not depend on the bundled triggers: they are only used for the final rescan.
        if not args.recover: raise
        print(f'Предупреждение: assets.zip недоступен ({error}). Восстановление пройдёт без пересканирования.',flush=True)
        assets=None
    global APPLE_DIRS, CONNECTION
    if args.wifi: CONNECTION='Network'
    APPLE_DIRS=[str(Path(p).resolve()) for p in args.apple_dir]
    # No shell, no compiler, no native executable bundled with the archive.
    check=subprocess.run(host_command()+['check'],input=json.dumps({'directories':APPLE_DIRS}),
                         capture_output=True,text=True,encoding='utf-8',timeout=20)
    frames=[json.loads(l.split(':',1)[1]) for l in check.stdout.splitlines() if l.startswith('CARRIER_SWAP_JSON:')]
    require(check.returncode==0 and frames and frames[-1].get('ok'),
            'Библиотеки Apple недоступны: '+str(frames[-1].get('error') if frames else check.stderr.strip()))
    if args.check:
        for k,v in environment_info():print(f'{k}: {v}')
        print('Триггеры целы, библиотеки Apple доступны; пакеты будут взяты из системы iPhone. Подключений к телефону не было.');return 0
    args.runs=args.runs.resolve()
    try:
        args.runs.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=args.runs,prefix='.write-test-'):pass
    except OSError:
        raise RuntimeError(f'Скрипт не может сохранить копии в папку: {args.runs}\n'
                           'Что сделать: закройте это окно, скопируйте всю папку CarrierSIM '
                           'в «Загрузки» и запустите оттуда.') from None
    with contextlib.suppress(OSError):start_session_log(args.runs)
    print('Разблокируйте iPhone и подтвердите доверие компьютеру. Закройте синхронизацию Finder/iTunes/Apple Devices.',flush=True)
    with operation_lock(args.runs):return asyncio.run(execute_with_retry(args,assets)) or 0


if __name__=='__main__':
    try:sys.exit(main())
    except KeyboardInterrupt:
        print('Прервано. Не удаляйте папку runs. Если запись уже началась, '+recover_hint()+'.',file=sys.stderr);sys.exit(130)
    except Exception as e:
        if not (len(sys.argv)>1 and sys.argv[1]=='--_host'):
            with contextlib.suppress(Exception):print_diagnostics(e)
        print('Ошибка:',str(e),file=sys.stderr);sys.exit(1)
