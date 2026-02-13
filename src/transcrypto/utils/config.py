# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto config library."""

from __future__ import annotations

import logging
import pathlib
import shutil
import sys
import tempfile
import threading
import venv
import zipfile
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
  """Reset the global config instance. If the current config is temporary, also deletes temp dir."""
  global __config_singleton  # noqa: PLW0603
  with __config_lock:
    if __config_singleton is not None and __config_singleton.temp:
      # if this is a temporary config, delete the temp directory to clean up
      logging.info(f'removing temporary config dir at {str(__config_singleton.dir)!r}')
      shutil.rmtree(__config_singleton.dir, ignore_errors=True)  # removes dir and all contents
    __config_singleton = None


def InitConfig(
  app_name: str,
  main_config: str,
  /,
  *,
  app_author: str | None = None,
  version: str | None = None,
  make_it_temporary: bool = False,
  fixed_dir: pathlib.Path | None = None,
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
    make_it_temporary (bool, optional): If True, will create a temporary directory for the
          config instead of using the standard platformdirs path. Useful for testing or for
          apps that want a temporary config. Defaults to False.
    fixed_dir (pathlib.Path | None, optional): For testing only, if given will use this instead
          of platformdirs or tempfile to determine the config directory. Do not use together
          with `make_it_temporary`. Defaults to None.

  Returns:
    _AppConfig: The global config instance.

  Raises:
    base.Error: if you call this more than once (or call with incorrect args)

  """
  global __config_singleton  # noqa: PLW0603
  with __config_lock:
    if __config_singleton is not None:
      raise base.Error(
        'calling InitConfig() more than once is forbidden; '
        'use Config() to get a config after first creation'
      )
    __config_singleton = AppConfig(
      app_name,
      main_config,
      app_author=app_author,
      version=version,
      make_it_temporary=make_it_temporary,
      fixed_dir=fixed_dir,
    )
    return __config_singleton


GetConfigDir = platformdirs.user_config_path


def _GetTemporaryConfigDir(
  appname: str, appauthor: str | None = None, version: str | None = None
) -> pathlib.Path:
  """Get a temporary config dir path.

  Useful for testing or for apps that want a temporary config. Will use tempfile.mkdtemp()
  to create a temporary directory and return its path as a pathlib.Path object.
  NOTE: The directory will NOT be automatically cleaned up - you must manually delete it
  when done, or rely on OS cleanup of temp directories.

  Args:
    appname (str): The name of the application.
    appauthor (str | None, optional): The name of the author or organization. Defaults to None.
    version (str | None, optional): The version of the application. Defaults to None.

  Returns:
    pathlib.Path: A temporary config directory path that has been created on the filesystem.

  """
  return pathlib.Path(
    tempfile.mkdtemp(
      prefix=f'{(appauthor + "_") if appauthor else ""}{appname}_',
      suffix=f'_{version}' if version else '',
    )
  )


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
    temp (bool): True if this config is temporary (i.e. created with make_it_temporary=True).

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
    make_it_temporary: bool = False,
    fixed_dir: pathlib.Path | None = None,
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
      make_it_temporary (bool, optional): If True, will create a temporary directory for the
          config instead of using the standard platformdirs path. Useful for testing or for
          apps that want a temporary config. Defaults to False.
      fixed_dir (pathlib.Path | None, optional): For testing only, if given will use this instead
          of platformdirs or tempfile to determine the config directory. Do not use together
          with `make_it_temporary`. Defaults to None.

    Raises:
      base.Error: if `app_name` or `main_config` is empty or if the config path is not a directory
          or if you set both `make_it_temporary` and `fixed_dir`

    """
    self.app_name: str = app_name.strip()
    self.main_config: str = main_config.strip()
    if not self.app_name or not self.main_config:
      raise base.Error('`app_name` and `main_config` must be non-empty strings')
    self.app_author: str | None = (
      app_author.strip() if app_author is not None and app_author.strip() else None
    )
    self.version: str | None = version.strip() if version is not None and version.strip() else None
    if make_it_temporary and fixed_dir is not None:
      raise base.Error('`make_it_temporary` and `fixed_dir` cannot both be set')  # for safety
    self.dir: pathlib.Path = (
      fixed_dir
      if fixed_dir is not None
      else (
        _GetTemporaryConfigDir(
          appname=self.app_name, appauthor=self.app_author, version=self.version
        )
        if make_it_temporary
        else GetConfigDir(appname=self.app_name, appauthor=self.app_author, version=self.version)
      )
    )
    self.path: pathlib.Path = self.dir / self.main_config
    self.temp: bool = make_it_temporary
    # create config dir if it doesn't exist
    if self.dir.exists():
      if not self.dir.is_dir():
        raise base.Error(f'config dir path {str(self.dir)!r} exists but is not a directory')
      logging.info(f'config dir already exists at {str(self.dir)!r}')
    else:
      self.dir.mkdir(parents=True, exist_ok=True)
      logging.warning(f'config dir did not exist, created new config dir at {str(self.dir)!r}')

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


def VenvPaths(venv_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
  """Return virtual environment paths for python and /bin.

  Useful for testing installed CLIs in a clean environment.

  Args:
      venv_dir (pathlib.Path): path to venv

  Returns:
      tuple[Path, Path]: (venv_python, venv_bin_dir)

  """
  is_win: bool = sys.platform.startswith('win')
  bin_dir: pathlib.Path = venv_dir / 'Scripts' if is_win else venv_dir / 'bin'
  return (bin_dir / 'python.exe' if is_win else bin_dir / 'python', bin_dir)


def FindConsoleScript(bin_dir: pathlib.Path, name: str) -> pathlib.Path:
  """Find the installed console script in the venv (platform-specific).

  Useful for testing installed CLIs in a clean environment.

  Args:
      bin_dir (pathlib.Path): directory containing the console scripts
      name (str): name of the console script to find

  Returns:
      pathlib.Path: path to the console script

  Raises:
      base.NotFoundError: if the console script is not found

  """
  # go through possible script names based on platform conventions; return the first one that exists
  for p in (
    bin_dir / name,  # *nix is typically just the name
    bin_dir / f'{name}.exe',  # Windows may have .exe/.cmd
    bin_dir / f'{name}.cmd',
  ):
    if p.exists():
      return p
  raise base.NotFoundError(f'Could not find console script {name!r} in {bin_dir}')


def WheelHasConsoleScripts(wheel: pathlib.Path, scripts: set[str]) -> bool:
  """Return True if the wheel defines the given console scripts.

  Args:
      wheel (pathlib.Path): wheel path
      scripts (set[str]): set of console script names to check for; case sensitive

  Returns:
      bool: True if all specified console scripts are found in the wheel

  """
  # open the wheel as a zip file and look for entry_points.txt; read
  try:
    with zipfile.ZipFile(wheel) as zf:
      entry_points: list[str] = [n for n in zf.namelist() if n.endswith('entry_points.txt')]
      if not entry_points:
        return False
      data: str = zf.read(entry_points[0]).decode('utf-8', errors='replace')
  except (OSError, zipfile.BadZipFile):
    return False
  # Minimal parse: ensure the [console_scripts] section contains the required names.
  in_console_scripts: bool = False
  found: set[str] = set()
  for raw_line in data.splitlines():
    line: str = raw_line.strip()
    if not line or line.startswith(('#', ';')):
      continue
    if line.startswith('[') and line.endswith(']'):
      in_console_scripts = line == '[console_scripts]'
      continue
    if in_console_scripts and '=' in line:
      name: str = line.split('=', 1)[0].strip()
      found.add(name)
  return scripts.issubset(found)


def EnsureWheel(repo: pathlib.Path, expected_version: str, scripts: set[str], /) -> pathlib.Path:
  """Build a wheel if needed; return path to the newest wheel in dist/.

  Args:
      repo (Path): path to the repository root
      expected_version (str): expected version string to match in the wheel filename
      scripts (set[str]): set of console script names to check for; case sensitive

  Raises:
      base.Error: if no wheel is found after building or not finding couldn't build a wheel

  Returns:
      Path: path to the newest wheel in dist/

  """
  dist_dir: pathlib.Path = repo / 'dist'
  dist_dir.mkdir(exist_ok=True)

  def _NewestWheel() -> pathlib.Path | None:
    # discover existing wheels
    wheels: list[pathlib.Path] = sorted(dist_dir.glob('*.whl'), key=lambda p: p.stat().st_mtime)
    # prefer an existing wheel that matches the current source version; otherwise build a new one.
    matching: list[pathlib.Path] = [w for w in wheels if f'-{expected_version}-' in w.name]
    if matching:
      newest: pathlib.Path = matching[-1]
      # if a stale wheel exists (e.g., built before console scripts were configured), rebuild.
      if WheelHasConsoleScripts(newest, scripts):
        return newest
    return None

  # try to find an existing wheel
  wheel: pathlib.Path | None = _NewestWheel()
  if wheel is not None:
    return wheel  # found
  # not found: build a new wheel
  poetry: str | None = shutil.which('poetry')
  if poetry is None:
    raise base.Error('`poetry` not found on PATH; cannot build wheel')
  base.Run([poetry, 'build', '-f', 'wheel'], cwd=repo)
  # now we must have a wheel!
  wheel = _NewestWheel()
  if wheel is not None:
    return wheel  # found
  raise base.Error(f'Wheel build succeeded but no `.whl` found in {str(dist_dir)!r}')


def EnsureAndInstallWheel(
  repository_root_dir: pathlib.Path,
  temporary_dir: pathlib.Path,
  expected_version: str,
  scripts: set[str],
  /,
) -> tuple[pathlib.Path, pathlib.Path]:
  """Ensure wheel exists (build if needed), create a `venv`, install the wheel.

  Args:
      repository_root_dir (pathlib.Path): path to the repository root
      temporary_dir (pathlib.Path): path to a temporary directory to use for the venv
      expected_version (str): expected version string to match in the wheel filename
      scripts (set[str]): set of console script names to check for; case sensitive

  Returns:
      tuple[pathlib.Path, pathlib.Path]: (venv_python, venv_bin_dir)

  Raises:
      base.InputError: if the wheel cannot be found or built, if the venv cannot be created,
          or if the wheel cannot be installed into the venv

  """
  # check to make sure directories exist, then ensure wheel exists (build if needed)
  if not repository_root_dir.is_dir() or not temporary_dir.is_dir():
    raise base.InputError('`repository_root_dir` and `temporary_dir` must be existing directories')
  if not scripts or not expected_version:
    raise base.InputError('`expected_version` and `scripts` must be non-empty')
  wheel: pathlib.Path = EnsureWheel(repository_root_dir, expected_version, scripts)
  # create an isolated venv (not using Poetry's .venv on purpose)
  venv_dir: pathlib.Path = temporary_dir / 'venv'
  venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
  venv_python: pathlib.Path
  venv_bin_dir: pathlib.Path
  venv_python, venv_bin_dir = VenvPaths(venv_dir)
  # install the wheel into the venv
  base.Run([str(venv_python), '-m', 'pip', 'install', '--no-cache-dir', '--upgrade', 'pip'])
  base.Run([str(venv_python), '-m', 'pip', 'install', '--no-cache-dir', str(wheel)])
  return (venv_python, venv_bin_dir)


def EnsureConsoleScriptsPrintExpectedVersion(
  venv_python: pathlib.Path, venv_bin_dir: pathlib.Path, expected_version: str, scripts: set[str], /
) -> dict[str, pathlib.Path]:
  """Ensure the console scripts print the expected version; return their paths.

  Useful for testing installed CLIs in a clean environment.

  Args:
      venv_python (pathlib.Path): path to the venv python executable
      venv_bin_dir (pathlib.Path): directory containing the console scripts
      expected_version (str): expected version string to match in the console script output
      scripts (set[str]): set of console script names to check for; case sensitive

  Returns:
      dict[str, pathlib.Path]: mapping of console script name to its path,
          including a 'python' key for the venv python executable

  Raises:
      base.Error: a console script does not print the expected version or if script is not found

  """
  cli_paths: dict[str, pathlib.Path] = {}
  for script in scripts:
    cli: pathlib.Path = FindConsoleScript(venv_bin_dir, script)
    result = base.Run([str(cli), '--version'])
    if (actual := result.stdout.strip()) != expected_version:
      raise base.Error(
        f'Console script {script!r} did not print version {expected_version!r}; got {actual!r}'
      )
    cli_paths[script] = cli
  cli_paths['python'] = venv_python
  return cli_paths


def CallGetConfigDirFromVEnv(venv_python: pathlib.Path, app_name: str) -> pathlib.Path:
  """Call a Python command in the venv to get the config dir path for the given app name.

  Args:
      venv_python (pathlib.Path): path to the venv python executable
      app_name (str): The name of the application.

  Returns:
      pathlib.Path: the config dir path returned by the command

  Raises:
      base.InputError: if the venv python executable does not exist or if `app_name` is empty

  """
  if not venv_python.exists():
    raise base.InputError(f'venv python not found at {str(venv_python)!r}')
  if not app_name:
    raise base.InputError('`app_name` must be a non-empty string')
  r2 = base.Run(
    [
      str(venv_python),
      '-c',
      f'from transcrypto.utils import config; print(config.GetConfigDir("{app_name}"))',
    ]
  )
  return pathlib.Path(r2.stdout.strip())
