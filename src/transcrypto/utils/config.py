# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto config library."""

from __future__ import annotations

import pathlib
import threading
from collections import abc

import platformdirs

from transcrypto.core import key
from transcrypto.utils import base

__config_lock: threading.RLock = threading.RLock()
__config_singleton: AppConfig | None = None


def Config() -> AppConfig:
  """Get the global config instance.

  Returns:
    _AppConfig: The global config instance.

  Raises:
    base.Error: if you call this before InitConfig()

  """
  with __config_lock:
    if __config_singleton is None:
      raise base.Error('Config() called before InitConfig()')
    return __config_singleton


def ResetConfig() -> None:
  """Reset the global config instance."""
  global __config_singleton  # noqa: PLW0603
  with __config_lock:
    __config_singleton = None


def InitConfig(
  app_name: str,
  main_config: str,
  /,
  *,
  app_author: str | None = None,
  version: str | None = None,
) -> AppConfig:
  """Initialize config singleton.

  If you have a CLI app that uses this, its pytests should call `ResetConsole()` in a fixture, like:

      from transcrypto.utils import config
      @pytest.fixture(autouse=True)
      def _reset_base_logging() -> None:
        config.ResetConfig()

  Args:
    app_name (str): The name of the application.
    main_config (str): The main config file name (e.g. 'config.toml'). You can add other
        config files later in the app dir if you want, but this is the one that will be used
        by default for loading/saving.
    app_author (str | None, optional): The name of the author or organization. Defaults to None.
        Affects the config path on Windows OS.
    version (str | None, optional): The version of the application. Defaults to None.

  Returns:
    _AppConfig: The global config instance.

  Raises:
    base.Error: if you call this more than once

  """
  global __config_singleton  # noqa: PLW0603
  with __config_lock:
    if __config_singleton is not None:
      raise base.Error(
        'calling InitConfig() more than once is forbidden; '
        'use Config() to get a config after first creation'
      )
    __config_singleton = AppConfig(app_name, main_config, app_author=app_author, version=version)
    return __config_singleton


GetConfigDir = platformdirs.user_config_path


class AppConfig:
  r"""Application config singleton.

  Attributes:
    app_name (str): The name of the application.
    main_config (str): The main config file name (e.g. 'config.toml'). You can add other
        config files later in the app dir if you want, but this is the one that will
        be used by default for loading/saving.
    app_author (str | None): The name of the author or organization. Mostly for Windows OS.
    version (str | None): The version of the application.
    dir (pathlib.Path): The path to the configuration directory.
    path (pathlib.Path): The main config file full path.

  The config directory `dir` is determined by `platformdirs.user_config_path()`,
  which typically resolves to:

  * On macOS: '/Users/[user]/Library/Application Support/[app_name]{/[version]}'
  * On Windows: 'C:\\Users\\[user]\\AppData\\Local{\\[app_author]}\\[app_name]{\\[version]}'
  * On Linux: '/home/[user]/.config/[app_name]{/[version]}'
  * On Android: '/data/data/com.myApp/shared_prefs/[app_name]{/[version]}'

  (See: <https://pypi.org/project/platformdirs/>)

  """

  def __init__(
    self,
    app_name: str,
    main_config: str,
    /,
    *,
    app_author: str | None = None,
    version: str | None = None,
  ) -> None:
    """Construct.

    Args:
      app_name (str): The name of the application.
      main_config (str): The main config file name (e.g. 'config.toml'). You can add other
          config files later in the app dir if you want, but this is the one that will be used
          by default for loading/saving.
      app_author (str | None, optional): The name of the author or organization. Defaults to None.
         Affects the config path on Windows OS.
      version (str | None, optional): The version of the application. Defaults to None.

    Raises:
      base.Error: if app_name or main_config is empty

    """
    self.app_name: str = app_name.strip()
    self.main_config: str = main_config.strip()
    if not self.app_name or not self.main_config:
      raise base.Error('`app_name` and `main_config` must be non-empty strings')
    self.app_author: str | None = app_author
    self.version: str | None = version
    self.dir: pathlib.Path = GetConfigDir(
      appname=self.app_name, appauthor=self.app_author, version=self.version
    )
    self.path: pathlib.Path = self.dir / self.main_config
    # create config dir if it doesn't exist
    self.dir.mkdir(parents=True, exist_ok=True)

  def Serialize[T](
    self,
    python_obj: T,
    /,
    *,
    config_name: str | None = None,
    compress: int | None = 3,
    encryption_key: key.Encryptor | None = None,
    silent: bool = False,
    pickler: abc.Callable[[T], bytes] = key.PickleGeneric,
  ) -> None:
    """Serialize a Python config object into a BLOB, optionally compress / encrypt / save to disk.

    SEE: transcrypto.core.key.Serialize() for more details on the arguments and behavior
    of this method, as it is a convenient wrapper for that method which fills in the file path
    based on the config dir and main_config.

    Args:
      python_obj (Any): serializable Python object
      config_name (str, optional): config name to save to (e.g. 'config.toml');
          if not given, will use self.main_config
      compress (int | None, optional): Compress level before encrypting/saving; -22 ≤ compress ≤ 22;
          None is no compression; default is 3, which is fast, see table above for other values
      encryption_key (Encryptor, optional): if given will encryption_key.Encrypt() data before save
      silent (bool, optional): if True will not log; default is False (will log)
      pickler (Callable[[Any], bytes], optional): if not given, will just be the `pickle` module;
          if given will be a method to convert any Python object to its `bytes` representation;
          PickleGeneric is the default, but another useful value is PickleJSON

    """
    config_name = config_name.strip() if config_name is not None and config_name.strip() else None
    file_path: pathlib.Path = self.path if config_name is None else self.dir / config_name
    key.Serialize(
      python_obj,
      file_path=str(file_path),
      compress=compress,
      encryption_key=encryption_key,
      silent=silent,
      pickler=pickler,
    )

  def DeSerialize[T](
    self,
    /,
    *,
    config_name: str | None = None,
    decryption_key: key.Decryptor | None = None,
    silent: bool = False,
    unpickler: abc.Callable[[bytes], T] = key.UnpickleGeneric,
  ) -> T:
    """Load (de-serializes) a config back to a Python object, optionally decrypting / decompressing.

    SEE: transcrypto.core.key.DeSerialize() for more details on the arguments and behavior
    of this method, as it is a convenient wrapper for that method which fills in the file path
    based on the config dir and main_config.

    Args:
      config_name (str, optional): config name to save to (e.g. 'config.toml');
          if not given, will use self.main_config
      decryption_key (Decryptor | None, optional): if given will decryption_key.Decrypt() data
          before decompressing/loading. Defaults to None.
      silent (bool, optional): if True will not log; default is False (will log). Defaults to False.
      unpickler (Callable[[bytes], Any], optional): if not given, will just be the `pickle` module;
          if given will be a method to convert a `bytes` representation back to a Python object;
          UnpickleGeneric is the default, but another useful value is UnpickleJSON.
          Defaults to UnpickleGeneric.

    Returns:
      De-Serialized Python config corresponding to data

    """
    config_name = config_name.strip() if config_name is not None and config_name.strip() else None
    file_path: pathlib.Path = self.path if config_name is None else self.dir / config_name
    return key.DeSerialize(
      file_path=str(file_path),
      decryption_key=decryption_key,
      silent=silent,
      unpickler=unpickler,
    )
