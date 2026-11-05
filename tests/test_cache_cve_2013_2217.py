# Regression tests for CVE-2013-2217: FileCache must not default to the fixed,
# world-predictable <tmp>/suds directory.

import os
import stat
import tempfile

import pytest

from suds.cache import FileCache, ObjectCache, DocumentCache


def test_default_location_is_not_shared_fixed_tmp_dir():
    cache = FileCache()
    assert cache.location != os.path.join(tempfile.gettempdir(), 'suds')
    assert os.path.isdir(cache.location)


def test_default_location_is_private():
    cache = FileCache()
    mode = stat.S_IMODE(os.stat(cache.location).st_mode)
    if os.name == 'posix':
        assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0
        assert os.stat(cache.location).st_uid == os.getuid()


def test_default_location_shared_within_process():
    assert FileCache().location == ObjectCache(days=1).location
    assert DocumentCache().location == FileCache().location


def test_explicit_location_is_respected(tmpdir):
    location = str(tmpdir.join('mycache'))
    cache = ObjectCache(location=location, days=1)
    assert cache.location == location
    cache.put('x', {'a': 1})
    assert cache.get('x') == {'a': 1}


def test_planted_pickle_in_old_location_is_not_loaded(tmpdir, monkeypatch):
    # Simulate another local user pre-creating the old fixed location and
    # planting a pickle there for the key the client will look up.
    import pickle
    fake_tmp = tmpdir.mkdir('systmp')
    old = fake_tmp.mkdir('suds')
    planted = ObjectCache(location=str(old), days=1)
    planted.put('wsdl-key', {'planted': True})
    assert planted.get('wsdl-key') == {'planted': True}

    monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(fake_tmp))
    # suds 0.4 bound gettempdir at import time as suds.cache.tmp.
    import suds.cache
    monkeypatch.setattr(suds.cache, 'tmp', lambda: str(fake_tmp), raising=False)
    cache = ObjectCache(days=1)
    assert not cache.location.startswith(str(old))
    assert cache.get('wsdl-key') is None
