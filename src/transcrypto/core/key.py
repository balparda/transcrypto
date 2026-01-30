# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto base CryptoKey class and protocols, including serialization."""

from __future__ import annotations

import abc as abstract
import dataclasses
import enum
import json
import logging
import pathlib
import pickle  # noqa: S403
import sys
from collections import abc
from typing import (
  Any,
  Protocol,
  Self,
  cast,
  final,
  runtime_checkable,
)

import zstandard

from transcrypto.utils import base, human, timer

# TODO: more consistent logging in whole project

# Crypto types: add bytes for cryptographic data; has to be encoded for JSON serialization
type CryptValue = bool | int | float | str | bytes | list[CryptValue] | dict[str, CryptValue] | None
type CryptDict = dict[str, CryptValue]
_JSON_DATACLASS_TYPES: set[str] = {
  # native support
  'int',
  'float',
  'str',
  'bool',
  # support for lists for now, but no nested lists or dicts yet
  'list[int]',
  'list[float]',
  'list[str]',
  'list[bool]',
  # need conversion/encoding: see CryptValue/CryptDict
  'bytes',
}

# these control the pickling of data, do NOT ever change, or you will break all databases
# <https://docs.python.org/3/library/pickle.html#pickle.DEFAULT_PROTOCOL>
_PICKLE_PROTOCOL = 4  # protocol 4 available since python v3.8 # do NOT ever change!
PickleGeneric: abc.Callable[[Any], bytes] = lambda o: pickle.dumps(o, protocol=_PICKLE_PROTOCOL)
UnpickleGeneric: abc.Callable[[bytes], Any] = pickle.loads  # noqa: S301
PickleJSON: abc.Callable[[base.JSONDict], bytes] = lambda d: json.dumps(
  d, separators=(',', ':')
).encode('utf-8')
UnpickleJSON: abc.Callable[[bytes], base.JSONDict] = lambda b: json.loads(b.decode('utf-8'))
_PICKLE_AAD = b'transcrypto.base.Serialize.1.0'  # do NOT ever change!
# these help find compressed files, do NOT change unless zstandard changes
_ZSTD_MAGIC_FRAME = 0xFD2FB528
_ZSTD_MAGIC_SKIPPABLE_MIN = 0x184D2A50
_ZSTD_MAGIC_SKIPPABLE_MAX = 0x184D2A5F


class CryptoError(base.Error):
  """Cryptographic exception (TransCrypto)."""


class CryptoInputType(enum.StrEnum):
  """Types of inputs that can represent arbitrary bytes."""

  # prefixes; format prefixes are all 4 bytes
  PATH = '@'  # @path on disk → read bytes from a file
  STDIN = '@-'  # stdin
  HEX = 'hex:'  # hex:deadbeef → decode hex
  BASE64 = 'b64:'  # b64:... → decode base64
  STR = 'str:'  # str:hello → UTF-8 encode the literal
  RAW = 'raw:'  # raw:... → byte literals via \\xNN escapes (rare but handy)


def DetectInputType(data_str: str, /) -> CryptoInputType | None:
  """Auto-detect `data_str` type, if possible.

  Args:
    data_str (str): data to process, putatively a bytes blob

  Returns:
    CryptoInputType | None: type if has a known prefix, None otherwise

  """
  data_str = data_str.strip()
  if data_str == CryptoInputType.STDIN:
    return CryptoInputType.STDIN
  for t in (
    CryptoInputType.PATH,
    CryptoInputType.STR,
    CryptoInputType.HEX,
    CryptoInputType.BASE64,
    CryptoInputType.RAW,
  ):
    if data_str.startswith(t):
      return t
  return None


def BytesFromInput(data_str: str, /, *, expect: CryptoInputType | None = None) -> bytes:  # noqa: C901, PLR0911, PLR0912
  """Parse input `data_str` into `bytes`. May auto-detect or enforce a type of input.

  Can load from disk ('@'). Can load from stdin ('@-').

  Args:
    data_str (str): data to process, putatively a bytes blob
    expect (CryptoInputType | None, optional): If not given (None) will try to auto-detect the
        input type by looking at the prefix on `data_str` and if none is found will suppose
        a 'str:' was given; if one of the supported CryptoInputType is given then will enforce
        that specific type prefix or no prefix

  Returns:
    bytes: data

  Raises:
    base.InputError: unexpected type or conversion error

  """
  data_str = data_str.strip()
  # auto-detect
  detected_type: CryptoInputType | None = DetectInputType(data_str)
  expect = CryptoInputType.STR if expect is None and detected_type is None else expect
  if detected_type is not None and expect is not None and detected_type != expect:
    raise base.InputError(
      f'Expected type {expect=} is different from detected type {detected_type=}'
    )
  # now we know they don't conflict, so unify them; remove prefix if we have it
  expect = detected_type if expect is None else expect
  assert expect is not None, 'should never happen: type should be known here'  # noqa: S101
  data_str = data_str.removeprefix(expect)
  # for every type something different will happen now
  try:
    match expect:
      case CryptoInputType.STDIN:
        # read raw bytes from stdin: prefer the binary buffer; if unavailable,
        # fall back to text stream encoded as UTF-8 (consistent with str: policy).
        stream = getattr(sys.stdin, 'buffer', None)
        if stream is None:
          text: str = sys.stdin.read()
          if not isinstance(text, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise base.InputError('sys.stdin.read() produced non-text data')  # noqa: TRY301
          return text.encode('utf-8')
        data: bytes = stream.read()
        if not isinstance(data, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
          raise base.InputError('sys.stdin.buffer.read() produced non-binary data')  # noqa: TRY301
        return data
      case CryptoInputType.PATH:
        if not pathlib.Path(data_str).exists():
          raise base.InputError(f'cannot find file {data_str!r}')  # noqa: TRY301
        return pathlib.Path(data_str).read_bytes()
      case CryptoInputType.STR:
        return data_str.encode('utf-8')
      case CryptoInputType.HEX:
        return base.HexToBytes(data_str)
      case CryptoInputType.BASE64:
        return base.EncodedToBytes(data_str)
      case CryptoInputType.RAW:
        return base.RawToBytes(data_str)
      case _:
        raise base.InputError(f'invalid type {expect!r}')  # noqa: TRY301
  except Exception as err:
    raise base.InputError(f'invalid input: {err}') from err


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class CryptoKey(abstract.ABC):
  """A cryptographic key."""

  @abstract.abstractmethod
  def __post_init__(self) -> None:
    """Check data."""
    # every sub-class of CryptoKey has to implement its own version of __post_init__()

  @abstract.abstractmethod
  def __str__(self) -> str:
    """Safe (no secrets) string representation of the key.

    Returns:
      string representation of the key without leaking secrets

    """
    # every sub-class of CryptoKey has to implement its own version of __str__()

  @final
  def __repr__(self) -> str:
    """Safe (no secrets) string representation of the key. Same as __str__().

    Returns:
      string representation of the key without leaking secrets

    """
    # concrete __repr__() delegates to the (abstract) __str__():
    # this avoids marking __repr__() abstract while still unifying behavior
    return self.__str__()

  @final
  def _DebugDump(self) -> str:
    """Debug dump of the key object. NOT for logging, NOT for regular use, EXPOSES secrets.

    We disable default __repr__() for the CryptoKey classes for security reasons, so we won't
    leak private key values into logs, but this method allows for explicit access to the
    class fields for debugging purposes by mimicking the usual dataclass __repr__().

    Returns:
      string with all the object's fields explicit values

    """
    cls: str = type(self).__name__
    parts: list[str] = []
    for field in dataclasses.fields(self):
      val: Any = getattr(self, field.name)  # getattr is fine with frozen/slots
      parts.append(f'{field.name}={val!r}')
    return f'{cls}({", ".join(parts)})'

  @final
  @property
  def _json_dict(self) -> base.JSONDict:
    """Dictionary representation of the object suitable for JSON conversion.

    Returns:
      JSONDict: representation of the object suitable for JSON conversion

    Raises:
      base.ImplementationError: object has types that are not supported in JSON

    """
    self_dict: CryptDict = dataclasses.asdict(self)
    for field in dataclasses.fields(self):
      # check the type is OK
      if field.type not in _JSON_DATACLASS_TYPES:
        raise base.ImplementationError(
          f'Unsupported JSON field {field.name!r}/{field.type} not in {_JSON_DATACLASS_TYPES}'
        )
      # convert types that we accept but JSON does not
      if field.type == 'bytes':
        self_dict[field.name] = base.BytesToEncoded(cast('bytes', self_dict[field.name]))
    return cast('base.JSONDict', self_dict)

  @final
  @property
  def json(self) -> str:
    """JSON representation of the object, tightly packed, not for humans.

    Returns:
      str: JSON representation of the object, tightly packed

    """
    return json.dumps(self._json_dict, separators=(',', ':'))

  @final
  @property
  def formatted_json(self) -> str:
    """JSON representation of the object formatted for humans.

    Returns:
      str: JSON representation of the object formatted for humans

    """
    return json.dumps(self._json_dict, indent=4, sort_keys=True)

  @final
  @classmethod
  def _FromJSONDict(cls, json_dict: base.JSONDict, /) -> Self:
    """Create object from JSON representation.

    Args:
      json_dict (base.JSONDict): JSON dict

    Returns:
      a CryptoKey object ready for use

    Raises:
      base.InputError: unexpected type/fields
      base.ImplementationError: unsupported JSON field

    """
    # check we got exactly the fields we needed
    cls_fields: set[str] = {f.name for f in dataclasses.fields(cls)}
    json_fields: set[str] = set(json_dict)
    if cls_fields != json_fields:
      raise base.InputError(
        f'JSON data decoded to unexpected fields: {cls_fields=} / {json_fields=}'
      )
    # reconstruct the types we meddled with inside self._json_dict
    for field in dataclasses.fields(cls):
      if field.type not in _JSON_DATACLASS_TYPES:
        raise base.ImplementationError(
          f'Unsupported JSON field {field.name!r}/{field.type} not in {_JSON_DATACLASS_TYPES}'
        )
      if field.type == 'bytes':
        json_dict[field.name] = base.EncodedToBytes(json_dict[field.name])  # type: ignore[assignment, arg-type]
    # build the object
    return cls(**json_dict)

  @final
  @classmethod
  def FromJSON(cls, json_data: str, /) -> Self:
    """Create object from JSON representation.

    Args:
      json_data (str): JSON string

    Returns:
      a CryptoKey object ready for use

    Raises:
      base.InputError: unexpected type/fields

    """
    # get the dict back
    json_dict: base.JSONDict = json.loads(json_data)
    if not isinstance(json_dict, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
      raise base.InputError(f'JSON data decoded to unexpected type: {type(json_dict)}')
    return cls._FromJSONDict(json_dict)

  @final
  @property
  def blob(self) -> bytes:
    """Serial (bytes) representation of the object.

    Returns:
      bytes, pickled, representation of the object

    """
    return self.Blob()

  @final
  def Blob(self, /, *, encryption_key: Encryptor | None = None, silent: bool = True) -> bytes:
    """Get serial (bytes) representation of the object with more options, including encryption.

    Args:
      encryption_key (Encryptor, optional): if given will encryption_key.Encrypt() data before save
      silent (bool, optional): if True (default) will not log

    Returns:
      bytes, pickled, representation of the object

    """
    return Serialize(
      self._json_dict, compress=-2, encryption_key=encryption_key, silent=silent, pickler=PickleJSON
    )

  @final
  @property
  def encoded(self) -> str:
    """Base-64 representation of the object.

    Returns:
      str, pickled, base64, representation of the object

    """
    return self.Encoded()

  @final
  def Encoded(self, /, *, encryption_key: Encryptor | None = None, silent: bool = True) -> str:
    """Base-64 representation of the object with more options, including encryption.

    Args:
      encryption_key (Encryptor, optional): if given will encryption_key.Encrypt() data before save
      silent (bool, optional): if True (default) will not log

    Returns:
      str, pickled, base64, representation of the object

    """
    return CryptoInputType.BASE64 + base.BytesToEncoded(
      self.Blob(encryption_key=encryption_key, silent=silent)
    )

  @final
  @property
  def hex(self) -> str:
    """Hexadecimal representation of the object.

    Returns:
      str, pickled, hexadecimal, representation of the object

    """
    return self.Hex()

  @final
  def Hex(self, /, *, encryption_key: Encryptor | None = None, silent: bool = True) -> str:
    """Hexadecimal representation of the object with more options, including encryption.

    Args:
      encryption_key (Encryptor, optional): if given will encryption_key.Encrypt() data before save
      silent (bool, optional): if True (default) will not log

    Returns:
      str, pickled, hexadecimal, representation of the object

    """
    return CryptoInputType.HEX + base.BytesToHex(
      self.Blob(encryption_key=encryption_key, silent=silent)
    )

  @final
  @property
  def raw(self) -> str:
    """Raw escaped binary representation of the object.

    Returns:
      str, pickled, raw escaped binary, representation of the object

    """
    return self.Raw()

  @final
  def Raw(self, /, *, encryption_key: Encryptor | None = None, silent: bool = True) -> str:
    """Raw escaped binary representation of the object with more options, including encryption.

    Args:
      encryption_key (Encryptor, optional): if given will encryption_key.Encrypt() data before save
      silent (bool, optional): if True (default) will not log

    Returns:
      str, pickled, raw escaped binary, representation of the object

    """
    return CryptoInputType.RAW + base.BytesToRaw(
      self.Blob(encryption_key=encryption_key, silent=silent)
    )

  @final
  @classmethod
  def Load(
    cls, data: str | bytes, /, *, decryption_key: Decryptor | None = None, silent: bool = True
  ) -> Self:
    """Load (create) object from serialized bytes or string.

    Args:
      data (str | bytes): if bytes is assumed from CryptoKey.blob/Blob(), and
          if string is assumed from CryptoKey.encoded/Encoded()
      decryption_key (Decryptor, optional): if given will decryption_key.Decrypt() data before load
      silent (bool, optional): if True (default) will not log

    Returns:
      a CryptoKey object ready for use

    Raises:
      base.InputError: decode error

    """
    # if this is a string, then we suppose it is base64
    if isinstance(data, str):
      data = BytesFromInput(data)
    # we now have bytes and we suppose it came from CryptoKey.blob()/CryptoKey.CryptoBlob()
    try:
      json_dict: base.JSONDict = DeSerialize(
        data=data, decryption_key=decryption_key, silent=silent, unpickler=UnpickleJSON
      )
      return cls._FromJSONDict(json_dict)
    except Exception as err:
      raise base.InputError(f'input decode error: {err}') from err


@runtime_checkable
class Encryptor(Protocol):
  """Abstract interface for a class that has encryption.

  Contract:
    - If algorithm accepts a `nonce` or `tag` these have to be handled internally by the
      implementation and appended to the `ciphertext`/`signature`.
    - If AEAD is supported, `associated_data` (AAD) must be authenticated. If not supported
      then `associated_data` different from None must raise InputError.

  Notes:
    The interface is deliberately minimal: byte-in / byte-out.
    Metadata like nonce/tag may be:
      - returned alongside `ciphertext`/`signature`, or
      - bundled/serialized into `ciphertext`/`signature` by the implementation.

  """

  @abstract.abstractmethod
  def Encrypt(self, plaintext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Encrypt `plaintext` and return `ciphertext`.

    Args:
      plaintext (bytes): Data to encrypt.
      associated_data (bytes, optional): Optional AAD for AEAD modes; must be
          provided again on decrypt

    Returns:
      bytes: Ciphertext; if a nonce/tag is needed for decryption, the implementation
      must encode it within the returned bytes (or document how to retrieve it)

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: internal crypto failures

    """


@runtime_checkable
class Decryptor(Protocol):
  """Abstract interface for a class that has decryption (see contract/notes in Encryptor)."""

  @abstract.abstractmethod
  def Decrypt(self, ciphertext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Decrypt `ciphertext` and return the original `plaintext`.

    Args:
      ciphertext (bytes): Data to decrypt (including any embedded nonce/tag if applicable)
      associated_data (bytes, optional): Optional AAD (must match what was used during encrypt)

    Returns:
      bytes: Decrypted plaintext bytes

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: internal crypto failures, authentication failure, key mismatch, etc

    """


@runtime_checkable
class Verifier(Protocol):
  """Abstract interface for asymmetric signature verify. (see contract/notes in Encryptor)."""

  @abstract.abstractmethod
  def Verify(
    self, message: bytes, signature: bytes, /, *, associated_data: bytes | None = None
  ) -> bool:
    """Verify a `signature` for `message`. True if OK; False if failed verification.

    Args:
      message (bytes): Data that was signed (including any embedded nonce/tag if applicable)
      signature (bytes): Signature data to verify (including any embedded nonce/tag if applicable)
      associated_data (bytes, optional): Optional AAD (must match what was used during signing)

    Returns:
      True if signature is valid, False otherwise

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: internal crypto failures, authentication failure, key mismatch, etc

    """


@runtime_checkable
class Signer(Protocol):
  """Abstract interface for asymmetric signing. (see contract/notes in Encryptor)."""

  @abstract.abstractmethod
  def Sign(self, message: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Sign `message` and return the `signature`.

    Args:
      message (bytes): Data to sign.
      associated_data (bytes, optional): Optional AAD for AEAD modes; must be
          provided again on decrypt

    Returns:
      bytes: Signature; if a nonce/tag is needed for decryption, the implementation
      must encode it within the returned bytes (or document how to retrieve it)

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: internal crypto failures

    """


def Serialize[T](
  python_obj: T,
  /,
  *,
  file_path: str | None = None,
  compress: int | None = 3,
  encryption_key: Encryptor | None = None,
  silent: bool = False,
  pickler: abc.Callable[[T], bytes] = PickleGeneric,
) -> bytes:
  """Serialize a Python object into a BLOB, optionally compress / encrypt / save to disk.

  Data path is:

    `obj` => [pickler] => (compress) => (encrypt) => (save to `file_path`) => return

  At every step of the data path the data will be measured, in bytes.
  Every data conversion will be timed. The measurements/times will be logged (once).

  Compression levels / speed can be controlled by `compress`. Use this as reference:

  | Level    | Speed       | Compression ratio       | Typical use case                        |
  | -------- | ------------| ------------------------| --------------------------------------- |
  | -5 to -1 | Fastest     | Poor (better than none) | Real-time / very latency-sensitive      |
  | 0…3      | Very fast   | Good ratio              | Default CLI choice, safe baseline       |
  | 4…6      | Moderate    | Better ratio            | Good compromise for general persistence |
  | 7…10     | Slower      | Marginally better ratio | Only if storage space is precious       |
  | 11…15    | Much slower | Slight gains            | Large archives, not for runtime use     |
  | 16…22    | Very slow   | Tiny gains              | Archival-only, multi-GB datasets        |

  Args:
    python_obj (Any): serializable Python object
    file_path (str, optional): full path to optionally save the data to
    compress (int | None, optional): Compress level before encrypting/saving; -22 ≤ compress ≤ 22;
        None is no compression; default is 3, which is fast, see table above for other values
    encryption_key (Encryptor, optional): if given will encryption_key.Encrypt() data before save
    silent (bool, optional): if True will not log; default is False (will log)
    pickler (Callable[[Any], bytes], optional): if not given, will just be the `pickle` module;
        if given will be a method to convert any Python object to its `bytes` representation;
        PickleGeneric is the default, but another useful value is PickleJSON

  Returns:
    bytes: serialized binary data corresponding to obj + (compression) + (encryption)

  """
  messages: list[str] = []
  with timer.Timer('Serialization complete', emit_log=False) as tm_all:
    # pickle
    with timer.Timer('PICKLE', emit_log=False) as tm_pickle:
      obj: bytes = pickler(python_obj)
    if not silent:
      messages.append(f'    {tm_pickle}, {human.HumanizedBytes(len(obj))}')
    # compress, if needed
    if compress is not None:
      compress = max(compress, -22)
      compress = min(compress, 22)
      with timer.Timer(f'COMPRESS@{compress}', emit_log=False) as tm_compress:
        obj = zstandard.ZstdCompressor(level=compress).compress(obj)
      if not silent:
        messages.append(f'    {tm_compress}, {human.HumanizedBytes(len(obj))}')
    # encrypt, if needed
    if encryption_key is not None:
      with timer.Timer('ENCRYPT', emit_log=False) as tm_crypto:
        obj = encryption_key.Encrypt(obj, associated_data=_PICKLE_AAD)
      if not silent:
        messages.append(f'    {tm_crypto}, {human.HumanizedBytes(len(obj))}')
    # optionally save to disk
    if file_path is not None:
      with timer.Timer('SAVE', emit_log=False) as tm_save:
        pathlib.Path(file_path).write_bytes(obj)
      if not silent:
        messages.append(f'    {tm_save}, to {file_path!r}')
  # log and return
  if not silent:
    logging.info(f'{tm_all}; parts:\n{"\n".join(messages)}')
  return obj


def DeSerialize[T](  # noqa: C901
  *,
  data: bytes | None = None,
  file_path: str | None = None,
  decryption_key: Decryptor | None = None,
  silent: bool = False,
  unpickler: abc.Callable[[bytes], T] = UnpickleGeneric,
) -> T:
  """Load (de-serializes) a BLOB back to a Python object, optionally decrypting / decompressing.

  Data path is:

    `data` or `file_path` => (decrypt) => (decompress) => [unpickler] => return object

  At every step of the data path the data will be measured, in bytes.
  Every data conversion will be timed. The measurements/times will be logged (once).
  Compression versus no compression will be automatically detected.

  Args:
    data (bytes | None, optional): if given, use this as binary data string (input);
        if you use this option, `file_path` will be ignored
    file_path (str | None, optional): if given, use this as file path to load binary data
        string (input); if you use this option, `data` will be ignored. Defaults to None.
    decryption_key (Decryptor | None, optional): if given will decryption_key.Decrypt() data before
        decompressing/loading. Defaults to None.
    silent (bool, optional): if True will not log; default is False (will log). Defaults to False.
    unpickler (Callable[[bytes], Any], optional): if not given, will just be the `pickle` module;
        if given will be a method to convert a `bytes` representation back to a Python object;
        UnpickleGeneric is the default, but another useful value is UnpickleJSON.
        Defaults to UnpickleGeneric.

  Returns:
    De-Serialized Python object corresponding to data

  Raises:
    base.InputError: invalid inputs
    base.CryptoError: internal crypto failures, authentication failure, key mismatch, etc

  """  # noqa: DOC502
  # test inputs
  if (data is None and file_path is None) or (data is not None and file_path is not None):
    raise base.InputError('you must provide only one of either `data` or `file_path`')
  if file_path and not pathlib.Path(file_path).exists():
    raise base.InputError(f'invalid file_path: {file_path!r}')
  if data and len(data) < 4:  # noqa: PLR2004
    raise base.InputError('invalid data: too small')
  # start the pipeline
  obj: bytes = data or b''
  messages: list[str] = [f'DATA: {human.HumanizedBytes(len(obj))}'] if data and not silent else []
  with timer.Timer('De-Serialization complete', emit_log=False) as tm_all:
    # optionally load from disk
    if file_path:
      assert not obj, 'should never happen: if we have a file obj should be empty'  # noqa: S101
      with timer.Timer('LOAD', emit_log=False) as tm_load:
        obj = pathlib.Path(file_path).read_bytes()
      if not silent:
        messages.append(f'    {tm_load}, {human.HumanizedBytes(len(obj))}, from {file_path!r}')
    # decrypt, if needed
    if decryption_key is not None:
      with timer.Timer('DECRYPT', emit_log=False) as tm_crypto:
        obj = decryption_key.Decrypt(obj, associated_data=_PICKLE_AAD)
      if not silent:
        messages.append(f'    {tm_crypto}, {human.HumanizedBytes(len(obj))}')
    # decompress: we try to detect compression to determine if we must call zstandard
    if (
      len(obj) >= 4  # noqa: PLR2004
      and (
        ((magic := int.from_bytes(obj[:4], 'little')) == _ZSTD_MAGIC_FRAME)
        or (_ZSTD_MAGIC_SKIPPABLE_MIN <= magic <= _ZSTD_MAGIC_SKIPPABLE_MAX)
      )
    ):
      with timer.Timer('DECOMPRESS', emit_log=False) as tm_decompress:
        obj = zstandard.ZstdDecompressor().decompress(obj)
      if not silent:
        messages.append(f'    {tm_decompress}, {human.HumanizedBytes(len(obj))}')
    elif not silent:
      messages.append('    (no compression detected)')
    # create the actual object = unpickle
    with timer.Timer('UNPICKLE', emit_log=False) as tm_unpickle:
      python_obj: T = unpickler(obj)
    if not silent:
      messages.append(f'    {tm_unpickle}')
  # log and return
  if not silent:
    logging.info(f'{tm_all}; parts:\n{"\n".join(messages)}')
  return python_obj
