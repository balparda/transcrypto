# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/app_config.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/config_test.py
"""

from __future__ import annotations

import pathlib
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
