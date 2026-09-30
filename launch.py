#!/usr/bin/env python3
"""Локальное окружение и меню запуска. Сам по себе телефон не изменяет."""
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import zipfile
from carriersim_version import VERSION

ROOT = Path(__file__).resolve().parent
UNCONFIRMED = 3  # carrier.py: written, but iOS did not confirm the chosen bundle


def run_carrier(python, args, **kwargs):
    # Ctrl+C reaches carrier.py too. The launcher must not kill it 0.25 s later (what
    # subprocess.run does on KeyboardInterrupt): carrier.py needs time to put Books back
    # and write its journal. So the launcher swallows SIGINT while carrier.py runs. A no-op
    # handler, not SIG_IGN: an ignored SIGINT would be inherited and carrier.py could not be stopped.
    previous = signal.signal(signal.SIGINT, lambda *_: None)
    try:
        return subprocess.run([str(python), '-u', str(ROOT / 'carrier.py'), *args], cwd=ROOT, **kwargs).returncode
    finally:
        signal.signal(signal.SIGINT, previous)


def check_writable():
    # .venv and runs (backups, journals) are created next to the script.
    try:
        with tempfile.NamedTemporaryFile(dir=ROOT, prefix='.write-test-'):
            pass
    except OSError:
        raise RuntimeError(f'Скрипт не может работать из этой папки: {ROOT}\n'
                           'Что сделать: закройте это окно, скопируйте всю папку CarrierSIM '
                           'в «Загрузки» и запустите оттуда.') from None


# pyimg4 (pulled in by pymobiledevice3) requires these compressors, but CarrierSIM never
# imports pyimg4. They ship wheels only up to Python 3.12, so on 3.13+ pip would need a
# C compiler. Empty placeholder distributions satisfy the requirement instead.
PLACEHOLDERS = (('pylzss', '0.3.4'), ('lzfse', '0.4.2'))


def placeholder_wheel(directory, name, version):
    info = f'{name}-{version}.dist-info'
    files = {f'{info}/METADATA': f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n'
                                 'Summary: CarrierSIM placeholder; the real package is not used\n',
             f'{info}/WHEEL': 'Wheel-Version: 1.0\nGenerator: carriersim\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    record = ''.join(f'{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(d.encode()).digest()).rstrip(b"=").decode()},'
                     f'{len(d.encode())}\n' for n, d in files.items()) + f'{info}/RECORD,,\n'
    path = Path(directory) / f'{name}-{version}-py3-none-any.whl'
    with zipfile.ZipFile(path, 'w') as archive:
        for n, d in files.items():
            archive.writestr(n, d)
        archive.writestr(f'{info}/RECORD', record)
    return str(path)


def install_dependencies(python, version):
    # Prefer an older release with a wheel over building a newer one from source.
    pip = [str(python), '-m', 'pip', 'install', '--disable-pip-version-check', '--prefer-binary']
    if version >= (3, 13):
        with tempfile.TemporaryDirectory() as directory:
            wheels = [placeholder_wheel(directory, n, v) for n, v in PLACEHOLDERS]
            if subprocess.run(pip + ['--no-deps', '--no-index', *wheels]).returncode:
                return False
    return not subprocess.run(pip + ['-r', str(ROOT / 'requirements.txt')]).returncode


def python_environment():
    if sys.version_info < (3, 11):
        raise RuntimeError('Нужен Python 3.11 или новее: https://www.python.org/downloads/')
    if sys.platform == 'win32' and sys.maxsize <= 2**32:
        raise RuntimeError('На Windows нужен Python x64.')
    env = ROOT / '.venv'
    python = env / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
    current = '%d.%d' % sys.version_info[:2]
    for attempt in range(2):
        if not env.exists():
            print('Создаю локальное окружение .venv…', flush=True)
            subprocess.run([sys.executable, '-m', 'venv', str(env)], check=True)
        if not python.is_file():
            raise RuntimeError('Папка .venv неполная или создана на другой ОС. Переименуйте её и повторите запуск.')
        probe = subprocess.run([str(python), '-c',
            'import sys; assert sys.version_info >= (3,11); '
            'assert sys.platform != "win32" or sys.maxsize > 2**32; '
            'print("%d.%d" % sys.version_info[:2])'], capture_output=True, text=True)
        if probe.returncode:
            raise RuntimeError('Python в .venv не подходит. Переименуйте папку .venv и повторите запуск.')
        version = probe.stdout.strip()
        dependencies = subprocess.run([str(python), '-c',
            'from importlib.metadata import version; '
            'assert version("pymobiledevice3") == "11.12.5"; '
            'from pymobiledevice3.services.afc import AfcService; '
            'from pymobiledevice3.services.installation_proxy import InstallationProxyService'], capture_output=True)
        if not dependencies.returncode:
            return python
        if version == current or attempt:
            break
        # A half-installed .venv from another Python (e.g. a failed 3.14 attempt) is rebuilt
        # with the interpreter the launcher picked; a working .venv is never touched.
        print(f'Пересоздаю .venv: было Python {version}, теперь {current}…', flush=True)
        shutil.rmtree(env)
    print('Устанавливаю зависимости в .venv. Для этого нужен интернет…', flush=True)
    if not install_dependencies(python, tuple(map(int, version.split('.')))):
        if tuple(map(int, version.split('.'))) >= (3, 13):
            raise RuntimeError(f'Не удалось установить зависимости для Python {version}.\n'
                               'Что сделать: установите Python 3.12 с python.org '
                               '(на Windows — «Windows installer (64-bit)» версии 3.12.10), '
                               'старый Python удалять не нужно. Затем запустите скрипт снова.')
        raise RuntimeError('Не удалось установить зависимости. Проверьте интернет и запустите скрипт снова.')
    return python


def menu(wifi=False):
    print('\n' + '─' * 56)
    print(f'  CarrierSIM {VERSION}  ·  Vodafone HU')
    print('  Один профиль для всех SIM · привязка по IMSI')
    print('  Исследование, разработка и тесты — Vladimir B / vlw')
    print('  vlwwwwww@gmail.com')
    print('─' * 56)
    print('  1  Установить профиль (по bundle.yaml)\n'
          '  2  Посмотреть SIM и план установки\n'
          '  3  Проверить компьютер и файлы\n\n'
          '  4  Вернуть штатный профиль (выбранной SIM или всем)\n'
          '  5  Восстановить после сбоя\n'
          '  6  Открыть справку\n'
          '  7  Выбрать другой профиль\n'
          '  8  Диагностика связи (IMS, VoWiFi, VoLTE, 5G) — только чтение\n'
          '  9  Проверка звонка (кодек, канал) — только чтение\n'
          f'  10 Связь с iPhone: {"Wi-Fi (эксперимент)" if wifi else "кабель"} — переключить\n\n'
          '  0  Выход\n')
    while True:
        choice = input('  Ваш выбор: ').strip()
        if choice == '0': return None
        if choice == '1': return []
        if choice == '2': return ['--status']
        if choice == '3': return ['--check']
        if choice == '6': return ['--help']
        if choice == '4': return ['--restore', '--sims', choose_sims('Для каких SIM вернуть штатный профиль?')]
        if choice == '5': return ['--recover']
        if choice == '7': return other_profile()
        if choice == '8': return ['--diagnose']
        if choice == '9': return ['--watch-call']
        if choice == '10': return 'wifi'
        print('Введите число от 0 до 10. Установка ещё не начата.')


def other_profile():
    print('\n  Имя системного пакета оператора на iPhone, как в /System/Library/Carrier Bundles/iPhone.\n'
          '  Например: O2_Germany, Swisscom_ch, Vodafone_hu. Регистр букв важен.\n'
          '  Этот профиль заменит bundle.yaml для выбранных SIM. Пустой ввод — вернуться в меню.')
    while True:
        name = input('  Профиль: ').strip().removesuffix('.bundle')
        if not name: return False
        if re.fullmatch(r'[A-Za-z0-9_]+', name): break
        print('  Только латинские буквы, цифры и _. Например: O2_Germany.')
    return ['--bundle', name, '--sims', choose_sims('На какие SIM установить?')]


def choose_sims(question):
    print(f'\n  {question}\n'
          '  1  SIM 1\n'
          '  2  SIM 2\n'
          '  Enter — обе (все найденные)')
    while True:
        sims = input('  SIM: ').strip()
        if sims in ('', '1', '2'): return sims or 'all'
        print('  Введите 1, 2 или нажмите Enter.')


def main():
    os.chdir(ROOT)
    check_writable()
    python = None
    if len(sys.argv) > 1:
        python = python_environment()
        return run_carrier(python, sys.argv[1:])
    wifi = False
    while True:
        args = menu(wifi)
        if args is None: return 0
        if args is False: continue
        if args == 'wifi':
            wifi = not wifi
            if wifi:
                print('\n  Режим Wi-Fi: все действия с телефоном пойдут без кабеля.\n'
                      '  Нужно заранее: доверие через кабель и в Finder/iTunes галка\n'
                      '  «Показывать этот iPhone, если он подключён к Wi-Fi». Одна сеть с компьютером.\n'
                      '  Сначала пункт 2, потом 1. Порядок проверки — в README, раздел про --wifi.')
            continue
        if wifi and args not in (['--check'], ['--help']): args = [*args, '--wifi']
        print('\n' + '─' * 56, flush=True)
        try:
            if python is None: python = python_environment()
            code = run_carrier(python, args, env={**os.environ, 'CARRIERSIM_MENU': '1'})
            if code == UNCONFIRMED:
                print('\nВыбор профиля не подтверждён. Подробности — в журнале операции.')
            elif code:
                print('\nДействие не завершено. Причина указана выше.')
        except Exception as error:
            print('\nОшибка запуска:', error)
        input('\nНажмите Enter, чтобы вернуться в главное меню…')


if __name__ == '__main__':
    try: sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print('\nЗапуск прерван. Если запись уже началась, сохраните runs и используйте восстановление.')
        sys.exit(130)
    except Exception as error:
        print('Ошибка запуска:', error, file=sys.stderr)
        sys.exit(1)
