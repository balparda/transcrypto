# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/app_config.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/config_test.py
"""

from __future__ import annotations

import pathlib
import subprocess  # noqa: S404
import tempfile
import zipfile
from unittest import mock

import pytest

from transcrypto.core import aes, key
from transcrypto.utils import base
from transcrypto.utils import config as app_config


@pytest.fixture(autouse=True)
def reset_config() -> None:
  """Reset config singleton before each test."""
  app_config.ResetConfig()


def test_get_config_dir() -> None:
  """Test GetConfigDir returns a Path object."""
  config_dir: pathlib.Path = app_config.GetConfigDir()
  assert isinstance(config_dir, pathlib.Path)
  # Test with parameters
  config_dir_with_params: pathlib.Path = app_config.GetConfigDir(
    appname='test_app', appauthor='test_author', version='1.0.0'
  )
  assert isinstance(config_dir_with_params, pathlib.Path)


def test_config_before_init_raises_error() -> None:
  """Test that calling Config() before InitConfig() raises an error."""
  with pytest.raises(base.Error, match='Config\\(\\) called before InitConfig\\(\\)'):
    app_config.Config()


def test_reset_config() -> None:
  """Test ResetConfig resets the singleton."""
  # Initialize config
  config: app_config.AppConfig = app_config.InitConfig('test_app', 'app_config.toml')
  assert config is not None
  # Confirm we can get it
  assert app_config.Config() is config
  # Reset
  app_config.ResetConfig()
  # Now calling Config() should raise error
  with pytest.raises(base.Error, match='Config\\(\\) called before InitConfig\\(\\)'):
    app_config.Config()


def test_init_config_basic() -> None:
  """Test InitConfig with basic parameters."""
  config: app_config.AppConfig = app_config.InitConfig('test_app', 'app_config.toml')
  assert config.app_name == 'test_app'
  assert config.main_config == 'app_config.toml'
  assert config.app_author is None
  assert config.version is None
  assert isinstance(config.dir, pathlib.Path)
  assert isinstance(config.path, pathlib.Path)
  assert config.path == config.dir / 'app_config.toml'
  # Verify singleton pattern works
  assert app_config.Config() is config


def test_init_config_with_all_parameters() -> None:
  """Test InitConfig with all parameters."""
  config: app_config.AppConfig = app_config.InitConfig(
    'test_app', 'app_config.toml', app_author='test_author', version='1.0.0'
  )
  assert config.app_name == 'test_app'
  assert config.main_config == 'app_config.toml'
  assert config.app_author == 'test_author'
  assert config.version == '1.0.0'
  assert isinstance(config.dir, pathlib.Path)
  assert isinstance(config.path, pathlib.Path)


def test_init_config_twice_raises_error() -> None:
  """Test that calling InitConfig() twice raises an error."""
  app_config.InitConfig('test_app', 'app_config.toml')
  with pytest.raises(
    base.Error, match=r'calling InitConfig\(\) more than once is forbidden.*use Config\(\)'
  ):
    app_config.InitConfig('another_app', 'other.toml')


def test_init_config_with_whitespace() -> None:
  """Test InitConfig strips whitespace from app_name and main_app_config."""
  config: app_config.AppConfig = app_config.InitConfig('  test_app  ', '  app_config.toml  ')
  assert config.app_name == 'test_app'
  assert config.main_config == 'app_config.toml'


def test_app_config_empty_app_name_raises_error() -> None:
  """Test AppConfig constructor raises error for empty app_name."""
  with pytest.raises(base.Error, match='`app_name` and `main_config` must be non-empty strings'):
    app_config.AppConfig('', 'app_config.toml')
  with pytest.raises(base.Error, match='`app_name` and `main_config` must be non-empty strings'):
    app_config.AppConfig('   ', 'app_config.toml')


def test_app_config_empty_main_config_raises_error() -> None:
  """Test AppConfig constructor raises error for empty main_app_config."""
  with pytest.raises(base.Error, match='`app_name` and `main_config` must be non-empty strings'):
    app_config.AppConfig('test_app', '')
  with pytest.raises(base.Error, match='`app_name` and `main_config` must be non-empty strings'):
    app_config.AppConfig('test_app', '   ')


def test_app_config_creates_directory() -> None:
  """Test that AppConfig creates the config directory if it doesn't exist."""
  # Use a mock to verify mkdir is called
  with mock.patch('transcrypto.utils.config.GetConfigDir') as mock_config_path:
    test_dir: pathlib.Path = pathlib.Path('/tmp/test_config_dir_doesnt_exist')  # noqa: S108  # cspell:disable-line
    mock_config_path.return_value = test_dir
    with mock.patch.object(pathlib.Path, 'mkdir') as mock_mkdir:
      config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
      mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
      assert config.dir == test_dir


def test_serialize_default_config_name(tmp_path: pathlib.Path) -> None:
  """Test Serialize with default config name."""
  # Use tmp_path for testing
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
    test_data: dict[str, str] = {'key': 'value', 'number': '42'}
    config.Serialize(test_data, silent=True)
    # Verify file was created at the right location
    assert config.path.exists()
    # Verify we can deserialize it back
    loaded_data: dict[str, str] = config.DeSerialize(silent=True)
    assert loaded_data == test_data


def test_serialize_custom_config_name(tmp_path: pathlib.Path) -> None:
  """Test Serialize with custom config name."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'main.toml')
    test_data: list[int] = [1, 2, 3, 4, 5]
    custom_config_name: str = 'custom_settings.dat'
    config.Serialize(test_data, config_name=custom_config_name, silent=True)
    # Verify file was created at custom location
    custom_path: pathlib.Path = config.dir / custom_config_name
    assert custom_path.exists()
    # Verify main config file was NOT created
    assert not config.path.exists()
    # Verify we can deserialize it back
    loaded_data: list[int] = config.DeSerialize(config_name=custom_config_name, silent=True)
    assert loaded_data == test_data


def test_serialize_with_whitespace_config_name(tmp_path: pathlib.Path) -> None:
  """Test Serialize strips whitespace from config_name."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'main.toml')
    test_data: str = 'test string'
    # Pass config name with whitespace
    config.Serialize(test_data, config_name='  custom.dat  ', silent=True)
    # Verify file was created with stripped name
    custom_path: pathlib.Path = config.dir / 'custom.dat'
    assert custom_path.exists()


def test_serialize_empty_config_name_uses_default(tmp_path: pathlib.Path) -> None:
  """Test Serialize with empty config_name uses default."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
    test_data: dict[str, int] = {'count': 10}
    # Pass empty config name (should use default)
    config.Serialize(test_data, config_name='   ', silent=True)
    # Verify main config file was created
    assert config.path.exists()


def test_serialize_with_compression(tmp_path: pathlib.Path) -> None:
  """Test Serialize with different compression levels."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
    test_data: str = 'x' * 1000  # Compressible data
    # Test with compression
    config.Serialize(test_data, compress=22, silent=True)
    loaded_data: str = config.DeSerialize(silent=True)
    assert loaded_data == test_data


def test_serialize_with_no_compression(tmp_path: pathlib.Path) -> None:
  """Test Serialize with no compression."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
    test_data: str = 'test data'
    # Test without compression
    config.Serialize(test_data, compress=None, silent=True)
    loaded_data: str = config.DeSerialize(silent=True)
    assert loaded_data == test_data


def test_serialize_with_encryption(tmp_path: pathlib.Path) -> None:
  """Test Serialize with encryption."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
    test_data: dict[str, str] = {'secret': 'password123'}
    encryption_key: aes.AESKey = aes.AESKey(key256=b'a' * 32)
    # Serialize with encryption
    config.Serialize(test_data, encryption_key=encryption_key, silent=True)
    # Deserialize with correct key
    loaded_data: dict[str, str] = config.DeSerialize(decryption_key=encryption_key, silent=True)
    assert loaded_data == test_data


def test_serialize_with_json_pickler(tmp_path: pathlib.Path) -> None:
  """Test Serialize with JSON pickler."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
    test_data: base.JSONDict = {'flag': True, 'count': 42, 'name': 'test'}
    # Use JSON pickler
    config.Serialize(test_data, pickler=key.PickleJSON, silent=True)
    loaded_data: base.JSONDict = config.DeSerialize(unpickler=key.UnpickleJSON, silent=True)
    assert loaded_data == test_data


def test_serialize_complex_scenario(tmp_path: pathlib.Path) -> None:
  """Test Serialize with encryption, compression, and custom config name."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'main.toml')
    test_data: dict[str, list[int]] = {'numbers': [1, 2, 3, 4, 5] * 100}
    encryption_key: aes.AESKey = aes.AESKey(key256=b'b' * 32)
    custom_name: str = 'encrypted_compressed.dat'
    # Serialize with all options
    config.Serialize(
      test_data,
      config_name=custom_name,
      compress=10,
      encryption_key=encryption_key,
      silent=True,
    )
    # Deserialize with all options
    loaded_data: dict[str, list[int]] = config.DeSerialize(
      config_name=custom_name, decryption_key=encryption_key, silent=True
    )
    assert loaded_data == test_data


def test_deserialize_nonexistent_file_raises_error(tmp_path: pathlib.Path) -> None:
  """Test DeSerialize raises error for nonexistent file."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'app_config.toml')
    # Verify file doesn't exist yet
    assert not config.path.exists()
    # Try to deserialize a file that doesn't exist
    with pytest.raises(base.InputError, match='invalid file_path'):
      config.DeSerialize(silent=True)


def test_app_config_path_construction() -> None:
  """Test that AppConfig constructs paths correctly."""
  config: app_config.AppConfig = app_config.InitConfig('my_app', 'settings.toml')
  assert config.path.name == 'settings.toml'
  assert config.path.parent == config.dir
  assert str(config.path).endswith('settings.toml')


def test_multiple_configs_in_same_dir(tmp_path: pathlib.Path) -> None:
  """Test creating and managing multiple config files in the same directory."""
  with mock.patch('transcrypto.utils.config.GetConfigDir', return_value=tmp_path):
    config: app_config.AppConfig = app_config.AppConfig('test_app', 'main.toml')
    # Create multiple config files
    data1: dict[str, str] = {'type': 'config1'}
    data2: dict[str, str] = {'type': 'config2'}
    data3: dict[str, str] = {'type': 'config3'}
    config.Serialize(data1, config_name='file1.dat', silent=True)
    config.Serialize(data2, config_name='file2.dat', silent=True)
    config.Serialize(data3, silent=True)  # Use default (main.toml)
    # Verify all files exist
    assert (config.dir / 'file1.dat').exists()
    assert (config.dir / 'file2.dat').exists()
    assert config.path.exists()
    # Verify we can load each independently
    loaded1: dict[str, str] = config.DeSerialize(config_name='file1.dat', silent=True)
    loaded2: dict[str, str] = config.DeSerialize(config_name='file2.dat', silent=True)
    loaded3: dict[str, str] = config.DeSerialize(silent=True)
    assert loaded1 == data1
    assert loaded2 == data2
    assert loaded3 == data3


def test_app_config_path_exists_but_is_file(tmp_path: pathlib.Path) -> None:
  """When the config path exists and is a file, AppConfig should raise.

  This covers the branch that raises `base.Error` with the message
  "config dir path {self.dir} exists but is not a directory".
  """
  # create a regular file where the config directory would be
  p: pathlib.Path = tmp_path / 'not_a_dir'
  p.write_text('not a dir', encoding='utf-8')
  # ensure AppConfig uses this path as the config dir
  with (
    mock.patch('transcrypto.utils.config.GetConfigDir', return_value=p),
    pytest.raises(base.Error, match=r'config dir path .* exists but is not a directory'),
  ):
    app_config.AppConfig('test_app', 'app_config.toml')


def test_make_it_temporary_creates_temp_dir() -> None:
  """Test that make_it_temporary=True creates a temporary directory."""
  config: app_config.AppConfig = app_config.InitConfig(
    'test_app', 'app_config.toml', make_it_temporary=True
  )
  # Verify temp attribute is set
  assert config.temp is True
  # Verify directory exists
  assert config.dir.exists()
  assert config.dir.is_dir()
  # Verify it's in the system temp directory
  assert str(config.dir).startswith(str(pathlib.Path(tempfile.gettempdir())))
  # Verify directory name contains app name
  assert 'test_app' in config.dir.name


def test_make_it_temporary_with_all_params() -> None:
  """Test make_it_temporary with app_author and version."""
  config: app_config.AppConfig = app_config.InitConfig(
    'my_app',
    'settings.toml',
    app_author='AuthorName',
    version='1.2.3',
    make_it_temporary=True,
  )
  assert config.temp is True
  assert config.dir.exists()
  # Verify directory name contains app_author and version
  assert 'AuthorName' in config.dir.name
  assert '1.2.3' in config.dir.name
  assert 'my_app' in config.dir.name


def test_fixed_dir_uses_provided_path(tmp_path: pathlib.Path) -> None:
  """Test that fixed_dir parameter uses the provided directory."""
  fixed_path: pathlib.Path = tmp_path / 'my_custom_config'
  config: app_config.AppConfig = app_config.InitConfig(
    'test_app', 'app_config.toml', fixed_dir=fixed_path
  )
  # Verify the directory matches
  assert config.dir == fixed_path
  # Verify temp attribute is False
  assert config.temp is False
  # Verify directory was created
  assert fixed_path.exists()
  assert fixed_path.is_dir()


def test_fixed_dir_with_existing_directory(tmp_path: pathlib.Path) -> None:
  """Test that fixed_dir works with an existing directory."""
  existing_dir: pathlib.Path = tmp_path / 'existing_dir'
  existing_dir.mkdir()
  # Add a file to verify it's not overwritten
  test_file: pathlib.Path = existing_dir / 'test.txt'
  test_file.write_text('existing content', encoding='utf-8')
  config: app_config.AppConfig = app_config.InitConfig(
    'test_app', 'app_config.toml', fixed_dir=existing_dir
  )
  assert config.dir == existing_dir
  assert config.temp is False
  # Verify existing file is still there
  assert test_file.exists()
  assert test_file.read_text(encoding='utf-8') == 'existing content'


def test_make_it_temporary_and_fixed_dir_raises_error() -> None:
  """Test that setting both make_it_temporary and fixed_dir raises an error."""
  with pytest.raises(base.Error, match='`make_it_temporary` and `fixed_dir` cannot both be set'):
    app_config.InitConfig(
      'test_app',
      'app_config.toml',
      make_it_temporary=True,
      fixed_dir=pathlib.Path('/tmp/test'),  # noqa: S108
    )


def test_fixed_dir_serialization(tmp_path: pathlib.Path) -> None:
  """Test Serialize/DeSerialize with fixed_dir."""
  fixed_path: pathlib.Path = tmp_path / 'custom_config'
  config: app_config.AppConfig = app_config.InitConfig(
    'test_app', 'config.json', fixed_dir=fixed_path
  )
  test_data: dict[str, int] = {'value': 42, 'count': 100}
  # Serialize data
  config.Serialize(test_data, silent=True)
  # Verify file was created in the fixed directory
  assert (fixed_path / 'config.json').exists()
  # Deserialize and verify
  loaded_data: dict[str, int] = config.DeSerialize(silent=True)
  assert loaded_data == test_data


def test_make_it_temporary_serialization() -> None:
  """Test Serialize/DeSerialize with make_it_temporary."""
  config: app_config.AppConfig = app_config.InitConfig(
    'test_app', 'data.bin', make_it_temporary=True
  )
  test_data: list[str] = ['alpha', 'beta', 'gamma']
  # Serialize data
  config.Serialize(test_data, silent=True)
  # Verify file was created
  assert config.path.exists()
  # Deserialize and verify
  loaded_data: list[str] = config.DeSerialize(silent=True)
  assert loaded_data == test_data


def test_reset_config_deletes_temp_dir() -> None:
  """Test ResetConfig removes the temporary directory when config.temp is True."""
  config: app_config.AppConfig = app_config.InitConfig(
    'test_app', 'data.bin', make_it_temporary=True
  )
  temp_dir: pathlib.Path = config.dir
  assert temp_dir.exists()
  app_config.ResetConfig()
  assert not temp_dir.exists()


def test_VenvPaths_unix(tmp_path: pathlib.Path) -> None:
  """Test VenvPaths returns correct unix paths."""
  with mock.patch('sys.platform', 'darwin'):
    python_path, bin_dir = app_config.VenvPaths(tmp_path)
    assert bin_dir == tmp_path / 'bin'
    assert python_path == tmp_path / 'bin' / 'python'


def test_VenvPaths_windows(tmp_path: pathlib.Path) -> None:
  """Test VenvPaths returns correct windows paths."""
  with mock.patch('sys.platform', 'win32'):
    python_path, bin_dir = app_config.VenvPaths(tmp_path)
    assert bin_dir == tmp_path / 'Scripts'
    assert python_path == tmp_path / 'Scripts' / 'python.exe'


def test_FindConsoleScript_found(tmp_path: pathlib.Path) -> None:
  """Test FindConsoleScript finds the bare name script."""
  script: pathlib.Path = tmp_path / 'my-script'
  script.write_text('#!/bin/sh\n', encoding='utf-8')
  result: pathlib.Path = app_config.FindConsoleScript(tmp_path, 'my-script')
  assert result == script


def test_FindConsoleScript_found_exe(tmp_path: pathlib.Path) -> None:
  """Test FindConsoleScript finds the .exe variant."""
  script: pathlib.Path = tmp_path / 'my-script.exe'
  script.write_text('dummy', encoding='utf-8')
  result: pathlib.Path = app_config.FindConsoleScript(tmp_path, 'my-script')
  assert result == script


def test_FindConsoleScript_found_cmd(tmp_path: pathlib.Path) -> None:
  """Test FindConsoleScript finds the .cmd variant."""
  script: pathlib.Path = tmp_path / 'my-script.cmd'
  script.write_text('dummy', encoding='utf-8')
  result: pathlib.Path = app_config.FindConsoleScript(tmp_path, 'my-script')
  assert result == script


def test_FindConsoleScript_not_found(tmp_path: pathlib.Path) -> None:
  """Test FindConsoleScript raises NotFoundError when no variant exists."""
  with pytest.raises(base.NotFoundError, match=r"Could not find console script 'nope'"):
    app_config.FindConsoleScript(tmp_path, 'nope')


def _make_wheel(tmp_path: pathlib.Path, entry_points_content: str | None) -> pathlib.Path:
  """Create a minimal .whl (zip) optionally containing entry_points.txt.

  Returns:
    Path to the created .whl file.

  """
  whl: pathlib.Path = tmp_path / 'pkg-1.0-py3-none-any.whl'
  with zipfile.ZipFile(whl, 'w') as zf:
    if entry_points_content is not None:
      zf.writestr('pkg-1.0.dist-info/entry_points.txt', entry_points_content)
  return whl


def test_WheelHasConsoleScripts_true(tmp_path: pathlib.Path) -> None:
  """Test WheelHasConsoleScripts returns True when scripts match."""
  content: str = '[console_scripts]\nmycli = pkg.cli:main\nother = pkg.other:run\n'
  whl: pathlib.Path = _make_wheel(tmp_path, content)
  assert app_config.WheelHasConsoleScripts(whl, {'mycli'}) is True
  assert app_config.WheelHasConsoleScripts(whl, {'mycli', 'other'}) is True


def test_WheelHasConsoleScripts_missing_script(tmp_path: pathlib.Path) -> None:
  """Test WheelHasConsoleScripts returns False when a script is missing."""
  content: str = '[console_scripts]\nmycli = pkg.cli:main\n'
  whl: pathlib.Path = _make_wheel(tmp_path, content)
  assert app_config.WheelHasConsoleScripts(whl, {'nope'}) is False


def test_WheelHasConsoleScripts_no_entry_points(tmp_path: pathlib.Path) -> None:
  """Test WheelHasConsoleScripts returns False when entry_points.txt is absent."""
  whl: pathlib.Path = _make_wheel(tmp_path, None)
  assert app_config.WheelHasConsoleScripts(whl, {'mycli'}) is False


def test_WheelHasConsoleScripts_bad_zip(tmp_path: pathlib.Path) -> None:
  """Test WheelHasConsoleScripts returns False for a corrupt/non-zip file."""
  bad: pathlib.Path = tmp_path / 'bad.whl'
  bad.write_bytes(b'not a zip')
  assert app_config.WheelHasConsoleScripts(bad, {'x'}) is False


def test_WheelHasConsoleScripts_no_console_scripts_section(tmp_path: pathlib.Path) -> None:
  """Test returns False when entry_points.txt has no [console_scripts] section."""
  content: str = '[gui_scripts]\nmycli = pkg.cli:main\n'
  whl: pathlib.Path = _make_wheel(tmp_path, content)
  assert app_config.WheelHasConsoleScripts(whl, {'mycli'}) is False


def test_WheelHasConsoleScripts_comments_and_blanks(tmp_path: pathlib.Path) -> None:
  """Test parser skips comments and blank lines correctly."""
  content: str = '# comment\n\n[console_scripts]\n; another comment\n\nmycli = pkg.cli:main\n'
  whl: pathlib.Path = _make_wheel(tmp_path, content)
  assert app_config.WheelHasConsoleScripts(whl, {'mycli'}) is True


def test_WheelHasConsoleScripts_section_switch(tmp_path: pathlib.Path) -> None:
  """Test parser stops collecting names when section switches."""
  content: str = (
    '[console_scripts]\nmycli = pkg.cli:main\n[other_section]\nnot-cli = pkg.other:run\n'
  )
  whl: pathlib.Path = _make_wheel(tmp_path, content)
  assert app_config.WheelHasConsoleScripts(whl, {'mycli'}) is True
  assert app_config.WheelHasConsoleScripts(whl, {'not-cli'}) is False


def test_WheelHasConsoleScripts_os_error(tmp_path: pathlib.Path) -> None:
  """Test returns False when an OSError occurs (e.g. file not found)."""
  missing: pathlib.Path = tmp_path / 'missing.whl'
  assert app_config.WheelHasConsoleScripts(missing, {'x'}) is False


def test_EnsureWheel_existing_good_wheel(tmp_path: pathlib.Path) -> None:
  """Test EnsureWheel returns an existing matching wheel."""
  dist_dir: pathlib.Path = tmp_path / 'dist'
  dist_dir.mkdir()
  content: str = '[console_scripts]\nmycli = pkg.cli:main\n'
  whl: pathlib.Path = dist_dir / 'pkg-1.0.0-py3-none-any.whl'
  with zipfile.ZipFile(whl, 'w') as zf:
    zf.writestr('pkg-1.0.0.dist-info/entry_points.txt', content)
  result: pathlib.Path = app_config.EnsureWheel(tmp_path, '1.0.0', {'mycli'})
  assert result == whl


def test_EnsureWheel_stale_wheel_rebuilds(tmp_path: pathlib.Path) -> None:
  """Test EnsureWheel rebuilds when the existing wheel is stale (missing console scripts)."""
  dist_dir: pathlib.Path = tmp_path / 'dist'
  dist_dir.mkdir()
  # Create a wheel that does NOT have the needed console scripts
  stale_whl: pathlib.Path = dist_dir / 'pkg-1.0.0-py3-none-any.whl'
  with zipfile.ZipFile(stale_whl, 'w') as zf:
    zf.writestr('pkg-1.0.0.dist-info/entry_points.txt', '[console_scripts]\nother = x:y\n')
  # After "poetry build" we need a wheel with the right scripts; mock everything
  good_content: str = '[console_scripts]\nmycli = pkg.cli:main\n'

  def _fake_run(cmd: list[str], /, **_kw: object) -> subprocess.CompletedProcess[str]:
    # Simulate poetry build creating a new wheel
    new_whl: pathlib.Path = dist_dir / 'pkg-1.0.0-py3-none-any.whl'
    with zipfile.ZipFile(new_whl, 'w') as zf:
      zf.writestr('pkg-1.0.0.dist-info/entry_points.txt', good_content)
    return subprocess.CompletedProcess(cmd, 0, '', '')

  with (
    mock.patch('shutil.which', return_value='/usr/local/bin/poetry'),
    mock.patch('transcrypto.utils.base.Run', side_effect=_fake_run),
  ):
    result: pathlib.Path = app_config.EnsureWheel(tmp_path, '1.0.0', {'mycli'})
  assert result.name == 'pkg-1.0.0-py3-none-any.whl'


def test_EnsureWheel_no_poetry_raises(tmp_path: pathlib.Path) -> None:
  """Test EnsureWheel raises when poetry is not on PATH."""
  dist_dir: pathlib.Path = tmp_path / 'dist'
  dist_dir.mkdir()
  with (
    mock.patch('shutil.which', return_value=None),
    pytest.raises(base.Error, match='`poetry` not found on PATH'),
  ):
    app_config.EnsureWheel(tmp_path, '1.0.0', {'mycli'})


def test_EnsureWheel_build_produces_nothing(tmp_path: pathlib.Path) -> None:
  """Test EnsureWheel raises when build succeeds but no matching wheel found."""
  dist_dir: pathlib.Path = tmp_path / 'dist'
  dist_dir.mkdir()
  with (
    mock.patch('shutil.which', return_value='/usr/local/bin/poetry'),
    mock.patch(
      'transcrypto.utils.base.Run',
      return_value=subprocess.CompletedProcess([], 0, '', ''),
    ),
    pytest.raises(base.Error, match=r'Wheel build succeeded but no `.whl` found'),
  ):
    app_config.EnsureWheel(tmp_path, '1.0.0', {'mycli'})


def test_EnsureAndInstallWheel_bad_dirs(tmp_path: pathlib.Path) -> None:
  """Test EnsureAndInstallWheel raises for non-existent directories."""
  with pytest.raises(
    base.InputError, match='`repository_root_dir` and `temporary_dir` must be existing directories'
  ):
    app_config.EnsureAndInstallWheel(tmp_path / 'nope', tmp_path, '1.0.0', {'cli'})


def test_EnsureAndInstallWheel_empty_scripts(tmp_path: pathlib.Path) -> None:
  """Test EnsureAndInstallWheel raises for empty scripts or version."""
  with pytest.raises(base.InputError, match='`expected_version` and `scripts` must be non-empty'):
    app_config.EnsureAndInstallWheel(tmp_path, tmp_path, '1.0.0', set())
  with pytest.raises(base.InputError, match='`expected_version` and `scripts` must be non-empty'):
    app_config.EnsureAndInstallWheel(tmp_path, tmp_path, '', {'cli'})


def test_EnsureAndInstallWheel_happy_path(tmp_path: pathlib.Path) -> None:
  """Test EnsureAndInstallWheel end-to-end with mocks."""
  repo: pathlib.Path = tmp_path / 'repo'
  repo.mkdir()
  temp: pathlib.Path = tmp_path / 'temp'
  temp.mkdir()
  venv_dir: pathlib.Path = temp / 'venv'
  fake_bin: pathlib.Path = venv_dir / 'bin'
  fake_python: pathlib.Path = fake_bin / 'python'
  fake_wheel: pathlib.Path = repo / 'dist' / 'pkg-1.0.0-py3-none-any.whl'
  with (
    mock.patch('transcrypto.utils.config.EnsureWheel', return_value=fake_wheel) as mock_ew,
    mock.patch('venv.EnvBuilder.create') as mock_venv,
    mock.patch('transcrypto.utils.base.Run') as mock_run,
  ):
    py, bd = app_config.EnsureAndInstallWheel(repo, temp, '1.0.0', {'cli'})
  mock_ew.assert_called_once_with(repo, '1.0.0', {'cli'})
  mock_venv.assert_called_once_with(venv_dir)
  assert mock_run.call_count == 2
  assert py == fake_python
  assert bd == fake_bin


def test_EnsureConsoleScriptsPrintExpectedVersion_ok(tmp_path: pathlib.Path) -> None:
  """Test happy path: all console scripts print the expected version."""
  # Create fake scripts
  script_a: pathlib.Path = tmp_path / 'alpha'
  script_a.write_text('dummy', encoding='utf-8')
  script_b: pathlib.Path = tmp_path / 'beta'
  script_b.write_text('dummy', encoding='utf-8')
  fake_python: pathlib.Path = tmp_path / 'python'
  with mock.patch(
    'transcrypto.utils.base.Run',
    return_value=subprocess.CompletedProcess([], 0, '2.0.0\n', ''),
  ):
    result: dict[str, pathlib.Path] = app_config.EnsureConsoleScriptsPrintExpectedVersion(
      fake_python, tmp_path, '2.0.0', {'alpha', 'beta'}
    )
  assert result['alpha'] == script_a
  assert result['beta'] == script_b
  assert result['python'] == fake_python


def test_EnsureConsoleScriptsPrintExpectedVersion_mismatch(tmp_path: pathlib.Path) -> None:
  """Test raises when version output does not match."""
  script: pathlib.Path = tmp_path / 'cli'
  script.write_text('dummy', encoding='utf-8')
  fake_python: pathlib.Path = tmp_path / 'python'
  with (
    mock.patch(
      'transcrypto.utils.base.Run',
      return_value=subprocess.CompletedProcess([], 0, '1.0.0\n', ''),
    ),
    pytest.raises(base.Error, match=r"did not print version '2.0.0'.*got '1.0.0'"),
  ):
    app_config.EnsureConsoleScriptsPrintExpectedVersion(fake_python, tmp_path, '2.0.0', {'cli'})


def test_CallGetConfigDirFromVEnv_ok(tmp_path: pathlib.Path) -> None:
  """Test happy path: get config dir from venv."""
  fake_python: pathlib.Path = tmp_path / 'python'
  fake_python.write_text('dummy', encoding='utf-8')
  expected: str = '/home/user/.config/myapp'
  with mock.patch(
    'transcrypto.utils.base.Run',
    return_value=subprocess.CompletedProcess([], 0, f'{expected}\n', ''),
  ):
    result: pathlib.Path = app_config.CallGetConfigDirFromVEnv(fake_python, 'myapp')
  assert result == pathlib.Path(expected)


def test_CallGetConfigDirFromVEnv_missing_python(tmp_path: pathlib.Path) -> None:
  """Test raises when venv python does not exist."""
  with pytest.raises(base.InputError, match=r'venv python not found'):
    app_config.CallGetConfigDirFromVEnv(tmp_path / 'nope', 'myapp')


def test_CallGetConfigDirFromVEnv_empty_app_name(tmp_path: pathlib.Path) -> None:
  """Test raises when app_name is empty."""
  fake_python: pathlib.Path = tmp_path / 'python'
  fake_python.write_text('dummy', encoding='utf-8')
  with pytest.raises(base.InputError, match='`app_name` must be a non-empty string'):
    app_config.CallGetConfigDirFromVEnv(fake_python, '')
