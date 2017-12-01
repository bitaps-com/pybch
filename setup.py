#!/usr/bin/python3
# coding: utf-8
# todo install libsec256 part
import os
import errno
import zipfile
import shutil
import subprocess
from distutils import log
from distutils.core import setup
from io import BytesIO
from bitcoinlib.exceptions import DownloadError, CompilationError
from subprocess import CalledProcessError


try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import URLError

setup(name='bitcoinlib',
      version='1.0.1',
      description='Bitcoin library',
      author='Alexsei Karpov',
      author_email='admin@bitaps.com',
      url='https://github.com/bitaps-com/bitcoinlib',
      packages=['bitcoinlib', ],
     )

LIB_SECP256K1_URL = "https://github.com/bitcoin-core/secp256k1/archive/master.zip"

level=log.INFO

def download_library():
    libdir = os.path.abspath("libsecp256k1")
    if os.path.exists(os.path.join(libdir, "autogen.sh")):
        # Library already downloaded
        return
    if not os.path.exists(libdir):
        log.info("Downloading libsecp256k1...")
        try:
            r = urlopen(LIB_SECP256K1_URL)
            if r.getcode() == 200:
                content = BytesIO(r.read())
                content.seek(0)
                with zipfile.ZipFile(content) as zf:
                    dirname = zf.namelist()[0].partition('/')[0]
                    zf.extractall()
                shutil.move(dirname, libdir)
            else:
                raise DownloadError(
                    "Unable to download secp256k1 library: HTTP-Status: %d" % r.getcode()
                )
        except URLError as ex:
            raise DownloadError("Unable to download secp256k1 library: %s" % ex.message)
        
def build_libsecp256k1():
    build_temp = os.path.abspath("build_temp")
    
    try:
        os.makedirs(build_temp)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise CompilationError("Compilation error: %s" % e.message)
    try:
        if not os.path.exists(os.path.abspath("libsecp256k1/configure")):
            log.info("Compiling libsecp256k1...")
            # configure script hasn't been generated yet
            autogen = os.path.abspath("libsecp256k1/autogen.sh")
            os.chmod(autogen, 0o755)

            subprocess.check_call(
                [autogen],
                cwd=os.path.abspath("libsecp256k1"),
            )
            subprocess.check_call(
                [os.path.abspath("libsecp256k1/configure")],
                cwd=build_temp,
            )
            subprocess.check_call(["make"], cwd=build_temp)
            subprocess.check_call(["make", "install"], cwd=build_temp)
            log.info("----------------------------------------------------------------------")

        log.info("Bitcoinlib-1.0.1 successfully installed!")
    except CalledProcessError as e:
        raise CompilationError("Compilation error: %s" % e)

try:
    download_library()
    build_libsecp256k1()
except SystemExit as e:
    log.error("Error loading source code libsecp256k1: %s" % e)
except CompilationError as e:
    log.error(e)
