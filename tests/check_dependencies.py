"""Import the actual device services without connecting to a phone."""
import sys
from importlib.metadata import metadata, version

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.afc import AfcService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.os_trace import OsTraceService
from pymobiledevice3.services.syslog import SyslogService
from pymobiledevice3.usbmux import list_devices

assert version('pymobiledevice3') == '11.12.5'
assert version('pyimg4') == '0.8.8'
# pyimg4 uses apple-compress instead of lzfse on macOS. The launcher still
# installs both placeholders on Python 3.13+ on every OS.
compressors = ['pylzss']
if sys.platform != 'darwin' or sys.version_info >= (3, 13):
    compressors.append('lzfse')
if sys.platform == 'darwin':
    assert version('apple-compress')
for name in compressors:
    placeholder = 'placeholder' in (metadata(name).get('Summary') or '')
    assert placeholder == (sys.version_info >= (3, 13)), name
print(f'Device service imports OK on Python {sys.version.split()[0]}')
