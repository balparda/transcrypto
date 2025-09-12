#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's SafeTrans(Crypto) command line interface: the safe version of TransCrypto.

See README.md for documentation on how to use.

Notes on the layout (quick mental model):

isprime
random bits|int|bytes|prime
hash sha256|sha512|file
aes new|frompass|encrypt|decrypt
rsa new|encrypt|decrypt|sign|verify
dsa shared|new|sign|verify
bid new|verify
sss new|shares|recover
doc md


Great question — crypto CLIs juggle a messy mix of bytes, strings, and files. The trick is to make sources and sinks explicit and consistent, and to give users a small set of composable rules that work the same across all subcommands.

Below is a battle-tested pattern (inspired by OpenSSL, age, gpg, minisign, libsodium tools) plus a compact argparse skeleton you can drop in.

⸻

Design principles
	1.	Uniform “data specifiers” for inputs
Any argument that represents bytes should accept the same mini-grammar:
	•	@path → read bytes from a file (@- means stdin)
	•	hex:deadbeef → decode hex
	•	b64:... → decode base64 (URL-safe b64u: optional)
	•	str:hello → UTF-8 encode the literal
	•	raw:... → byte literals via \\xNN escapes (rare but handy)
Integers and enums are not data specs; they’re normal flags (--bits 256, --curve ed25519).
	2.	Explicit output format & sink
Split format from destination:
	•	Format (mutually exclusive): --out-raw | --out-hex | --out-b64 | --out-json
	•	Destination: --out - (stdout, default) or --out path
	•	Multi-file outputs use --out-prefix /path/to/prefix (e.g., write prefix.key, prefix.pub)
	3.	Streaming defaults
	•	If an operation produces a single blob, default to stdout.
	•	If stdout is a TTY and format is binary, refuse unless --force or a non-TTY sink is chosen.
	4.	Schema for structured results
When outputs are multi-field (e.g., keygen with pub+priv), offer --out-json with stable field names and base64/hex encodings. Pair with --out-prefix for file emission.
	5.	Predictable subcommands & option names
Keep verbs clear and consistent:
	•	rand, hash, kdf, enc, dec, sign, verify, mac, keygen, derive, wrap, unwrap.
Reuse the same flag names everywhere (--key, --aad, --nonce, --msg).
	6.	File type inference is a bonus, not a rule
You may infer formats from extensions (.pem, .der, .jwk, .b64, .hex), but never rely on it: users can always override using data specifiers or --in-format/--key-format.
	7.	Safety foot-guns removed
	•	Private key outputs default to files with 0600 perms; refuse TTY unless --force.
	•	Zeroize sensitive buffers where feasible.
	•	Don’t echo secrets to logs; support --quiet.
	8.	Machine-friendly behavior
	•	Exit codes: 0 ok, 1 usage/validation error, 2 crypto failure (verification failed), 3 I/O error.
	•	--json responses are single-line by default; add --pretty for humans.

⸻

Mini-grammar (inputs)

EBNF:

DataSpec  := '@' Path
           | 'hex:' HexString
           | 'b64:' Base64String
           | 'b64u:' Base64UrlString
           | 'str:' Utf8Text
           | 'raw:' BackslashEscapes
           | '-'        ; shorthand for '@-'

Examples:
	•	--msg @message.bin
	•	--msg - (stdin)
	•	--key @id_ed25519 or --key @key.pem
	•	--aad str:metadata-v1
	•	--nonce hex:00112233...

For params that must be integers, be generous but explicit:
	•	--bits 2048
	•	Allow suffixes: --bytes 64, --duration 2h, --iters 1M.

⸻

Output policy
	•	Single blob:
	•	default sink: stdout
	•	default format: hex for short (<1KiB) unknown blobs? (or pick a project-wide default)
	•	user can force: --out-b64, --out-raw, --out-hex
	•	sink override: --out path
	•	Multi-artifact:
	•	--out-prefix prefix → prefix.pub, prefix.key, etc.
	•	OR --out-json to emit a single structured result (fields encoded as hex/b64)
	•	Optional --armor synonym for --out-b64 on legacy-style commands

⸻

Subcommand layout (suggested)
	•	rand → --bytes N → bytes
	•	hash → --alg sha256 --msg DataSpec → digest
	•	mac → --alg hmac-sha256 --key DataSpec --msg DataSpec → tag
	•	enc/dec → --alg chacha20-poly1305 --key --nonce --aad --in DataSpec
	•	sign/verify → --alg ed25519 --key/--pub --msg
	•	keygen → --alg ed25519 [writes files or JSON]
	•	kdf → --alg hkdf-sha256 --ikm --salt --info --bytes N

Every subcommand accepts the shared output flags and --quiet/--verbose.

⸻

UX examples

# Random 32 bytes to stdout, base64
tool rand --bytes 32 --out-b64

# SHA-256 of a file to hex on stdout
tool hash --alg sha256 --msg @file.bin --out-hex

# Encrypt file, AAD as literal string, nonce as hex; write ciphertext to file
tool enc --alg chacha20-poly1305 \
  --key @key.bin --nonce hex:001122... --aad str:invoice-2025-09 \
  --in @plain.bin --out cipher.bin --out-raw

# Sign from stdin, key from file, tag to stdout base64
cat message | tool sign --alg ed25519 --key @sk --msg - --out-b64

# Verify (exit code 0 on success, 2 on failure)
tool verify --alg ed25519 --pub @pk --msg @msg.bin --sig b64:ABCD...

# Keypair to files with secure perms
tool keygen --alg ed25519 --out-prefix ~/.keys/alice   # writes alice.key 0600, alice.pub 0644

# Same keypair as JSON (machine-friendly)
tool keygen --alg ed25519 --out-json | jq .


⸻

argparse skeleton (2-space indents, single quotes)

import argparse, base64, binascii, os, sys, json, stat

# ---------- Data parsing ----------

class UsageError(Exception): pass

def read_dataspec(s: str) -> bytes:
  if s == '-' or s == '@-':
    return sys.stdin.buffer.read()
  if s.startswith('@'):
    path = s[1:]
    with open(path, 'rb') as f:
      return f.read()
  if s.startswith('hex:'):
    try:
      return binascii.unhexlify(s[4:].strip())
    except binascii.Error as e:
      raise UsageError(f'invalid hex: {e}')
  if s.startswith('b64:') or s.startswith('b64u:'):
    data = s.split(':', 1)[1]
    altchars = b'-_' if s.startswith('b64u:') else None
    try:
      return base64.b64decode(data, validate=True, altchars=altchars)
    except binascii.Error as e:
      raise UsageError(f'invalid base64: {e}')
  if s.startswith('str:'):
    return s[4:].encode('utf-8')
  if s.startswith('raw:'):
    return bytes(s[4:], 'utf-8').decode('unicode_escape').encode('latin1')
  raise UsageError('expected DataSpec like @path, -, hex:, b64:, b64u:, str:, raw:')

def parse_int(s: str) -> int:
  mult = 1
  if s.lower().endswith('k'):
    mult, s = 1024, s[:-1]
  elif s.lower().endswith('m'):
    mult, s = 1024*1024, s[:-1]
  try:
    n = int(s, 0)
  except ValueError:
    raise UsageError('invalid integer')
  return n * mult

# ---------- Output handling ----------

def write_single_blob(data: bytes, args):
  if args.out == '-' and sys.stdout.isatty() and args.out_raw and not args.force:
    raise UsageError('refusing to print binary to TTY (use --force or --out FILE)')
  if args.out_hex:
    out = binascii.hexlify(data).decode('ascii')
    out_bytes = (out + '\n').encode()
  elif args.out_b64:
    out = base64.b64encode(data).decode('ascii')
    out_bytes = (out + '\n').encode()
  elif args.out_json:
    payload = {'data_b64': base64.b64encode(data).decode('ascii')}
    out_bytes = (json.dumps(payload, indent=2 if args.pretty else None) + '\n').encode()
  else:
    # raw
    out_bytes = data

  if args.out == '-' or args.out is None:
    sys.stdout.buffer.write(out_bytes)
  else:
    mode = 0o600 if getattr(args, 'sensitive', False) else 0o644
    with open(args.out, 'wb') as f:
      f.write(out_bytes)
    os.chmod(args.out, mode)

def write_prefixed(files: dict[str, bytes], prefix: str, sensitive_keys=('key', 'sk', 'priv')):
  if not prefix:
    raise UsageError('must provide --out-prefix for multi-file outputs')
  for suffix, content in files.items():
    path = f'{prefix}.{suffix}'
    mode = 0o600 if any(s in suffix for s in sensitive_keys) else 0o644
    with open(path, 'wb') as f:
      f.write(content)
    os.chmod(path, mode)
  return [f'{prefix}.{s}' for s in files]

# ---------- Subcommands ----------

def cmd_rand(args):
  n = parse_int(args.bytes)
  data = os.urandom(n)
  write_single_blob(data, args)

def cmd_hash(args):
  import hashlib
  msg = read_dataspec(args.msg)
  h = hashlib.new(args.alg)
  h.update(msg)
  write_single_blob(h.digest(), args)

def cmd_keygen(args):
  # placeholder example: ed25519 using cryptography
  from cryptography.hazmat.primitives.asymmetric import ed25519
  from cryptography.hazmat.primitives import serialization
  sk = ed25519.Ed25519PrivateKey.generate()
  pk = sk.public_key()

  sk_bytes = sk.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
  )
  pk_bytes = pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
  )

  if args.out_json:
    obj = {
      'alg': 'ed25519',
      'sk_b64': base64.b64encode(sk_bytes).decode('ascii'),
      'pk_b64': base64.b64encode(pk_bytes).decode('ascii'),
    }
    payload = json.dumps(obj, indent=2 if args.pretty else None) + '\n'
    sys.stdout.write(payload)
    return

  if args.out_prefix:
    write_prefixed({'key': sk_bytes, 'pub': pk_bytes}, args.out_prefix)
  else:
    # default: write secret to file, pub to stdout hex
    args.sensitive = True
    if not args.out:
      raise UsageError('provide --out (private key) or use --out-prefix/--out-json')
    write_single_blob(sk_bytes, args)
    # print pub to stderr for visibility without mixing streams
    pub_hex = binascii.hexlify(pk_bytes).decode('ascii')
    print(f'public key (hex): {pub_hex}', file=sys.stderr)

# ---------- Parser ----------

def build_parser():
  p = argparse.ArgumentParser(prog='tool', description='Crypto toolbox')
  p.add_argument('--quiet', action='store_true')
  p.add_argument('--verbose', action='store_true')

  out = argparse.ArgumentParser(add_help=False)
  g = out.add_mutually_exclusive_group()
  g.add_argument('--out-raw', dest='out_raw', action='store_true')
  g.add_argument('--out-hex', dest='out_hex', action='store_true')
  g.add_argument('--out-b64', dest='out_b64', action='store_true')
  g.add_argument('--out-json', dest='out_json', action='store_true')
  out.add_argument('--pretty', action='store_true')
  out.add_argument('--out', default='-')
  out.add_argument('--out-prefix')
  out.add_argument('--force', action='store_true')

  sub = p.add_subparsers(dest='cmd', required=True)

  pr = sub.add_parser('rand', parents=[out], help='random bytes')
  pr.add_argument('--bytes', required=True, help='number of bytes (e.g., 32, 1k)')
  pr.set_defaults(func=cmd_rand)

  ph = sub.add_parser('hash', parents=[out], help='hash message')
  ph.add_argument('--alg', required=True, choices=['sha256','sha512','blake2b'])
  ph.add_argument('--msg', required=True, help='DataSpec')
  ph.set_defaults(func=cmd_hash)

  pk = sub.add_parser('keygen', parents=[out], help='generate keypair')
  pk.add_argument('--alg', required=True, choices=['ed25519'])
  pk.set_defaults(func=cmd_keygen)

  return p

def main(argv=None):
  parser = build_parser()
  try:
    args = parser.parse_args(argv)
    # default to raw unless an encoding flag chosen
    if not (args.out_hex or args.out_b64 or args.out_json):
      args.out_raw = True
    args.func(args)
  except UsageError as e:
    print(f'error: {e}', file=sys.stderr)
    sys.exit(1)

if __name__ == '__main__':
  main()


⸻

How other tools approach it (patterns to copy)
	•	OpenSSL: -in/-out for files; PEM/DER auto-detected by headers; -passin schemes (file:, env:) — good precedent for scheme-style sources.
	•	GnuPG: --armor (base64) vs raw; refuses to dump secrets to TTY without explicit flags; separate --output vs stdout.
	•	age / minisign: simple verbs, -i for identity (key file), -a/--armor for base64, defaults to stdout for single outputs.
	•	libsodium CLI: clear distinction between --bin, --hex, --base64 across commands.

These all lean on: consistent flags, scheme prefixes for inputs, explicit armor flags, and safe defaults.

⸻

Gotchas & tips
	•	Binary to TTY: protect users by default (refuse unless --force).
	•	Permissions: set 0600 for secrets; warn if file exists unless --overwrite.
	•	Determinism: --deterministic where relevant (tests, vectors).
	•	Stateful formats: PEM/JWK support is valuable; expose --key-format {raw,pem,jwk} and auto-detect with override.
	•	AAD & friends: treat as DataSpec (so users can pass str: or b64: seamlessly).
	•	Exit code semantics: especially verify → 2 on bad signature (distinguish from parse errors).
	•	Docs: put the DataSpec grammar and examples at the top of --help for every subcommand.

⸻

If you want, tell me a couple of concrete operations you’ll ship first (e.g., ed25519 sign/verify, chacha20-poly1305 enc/dec, hkdf), and I’ll tailor the subparsers and validators for those right away.

Awesome list. Here’s a clean, consistent CLI contract for each item—built on the “DataSpec + output/sink” pattern we discussed. I’ll give you: (1) command shapes with flags, inputs/outputs, and exit-code behavior, and (2) an argparse scaffold you can paste in and extend.

I’m sticking to 2-space indents and single quotes.

⸻

Shared conventions (recap)
	•	DataSpec for any bytes: @path, -, hex:…, b64:…, b64u:…, str:…, raw:…
	•	Output: --out-{raw,hex,b64,json} (one of), --out -|PATH, --out-prefix PREFIX
	•	Safety: secrets written with 0600, refuse binary to TTY unless --force
	•	Exit codes: 0=ok, 1=usage/validation, 2=cryptographic failure (e.g., verify false), 3=I/O

⸻

Commands & flags

1) isprime
	•	Purpose: primality test for large integers
	•	Inputs
	•	--n INT (required). Accept decimal or 0x…
	•	--rounds R (Miller–Rabin reps, default 40)
	•	Output
	•	Default: true/false\n on stdout
	•	--out-json → {"n":"…","probable_prime":true,"rounds":40,"confidence":"1-2^-40"}
	•	Exit codes: 0 always if test ran; optionally --expect {prime,composite} makes exit 0 only if matched, else 2.

2) rand

Generates randomness in various shapes.
	•	Submodes (mutually exclusive):
	•	rand bytes --bytes N
	•	rand int --bits N  (uniform in [0, 2^N) as big-endian integer)
	•	rand bits --bits N (ASCII 0/1 string unless --out-raw)
	•	rand prime --bits N [--safe] [--public-exp E] (safe → p s.t. (p-1)/2 prime)
	•	Output: single blob (respect --out-*). For int, if textual, print base-10; if --out-hex, print hex; --out-raw prints big-endian bytes.

3) hash
	•	Inputs:
	•	--alg {sha256,sha512,blake2b} (extend as needed)
	•	--msg DataSpec (use @file for files; - for stdin)
	•	Output: digest (default hex); support --out-{hex,b64,raw,json}
	•	JSON: {"alg":"sha256","digest_b64":"…"}
	•	Notes: If users say “file”, they can just pass --msg @path.

4) aes

Symmetric crypto. Keep keys as DataSpec.
	•	Common flags:
	•	--mode {gcm,ctr,cbc} (default gcm)
	•	--key DataSpec or --from-pass str:PASSWORD --kdf {argon2id,pbkdf2} [--salt DataSpec] [--iters N] [--mem-mb N] [--parallelism N]
	•	--iv|--nonce DataSpec (if omitted, auto-generate & emit alongside ciphertext)
	•	--aad DataSpec (GCM)
	•	Subcommands:
	•	aes new --size {128,192,256} → random key bytes (sensitive out policy)
	•	aes frompass ... --size {128,192,256} → derived key bytes
	•	aes encrypt --in DataSpec [common flags]
	•	Output:
	•	Default single-part format (GCM): emit a compact JSON unless user picks a raw format:
	•	JSON: {"mode":"gcm","nonce_b64":"…","aad_b64":"…","ct_b64":"…","tag_b64":"…"}
	•	Or with --out-raw: raw nonce||ct||tag (define ordering), document it clearly.
	•	aes decrypt --in DataSpec [common flags]
	•	Accept either JSON bundle or raw concatenation (auto-detect unless --in-format {json,raw}).
	•	Exit codes: 2 on auth/tag failure.

5) rsa
	•	Subcommands:
	•	rsa new --bits N [--e 65537]
	•	Output:
	•	--out-prefix PREFIX → PREFIX.key (PKCS#1 or PKCS#8 raw/DER/PEM per --format), PREFIX.pub
	•	or --out-json → {"alg":"rsa","n_b64":"…","e":65537,"d_b64":"…","pkcs8_pem":"…"}
	•	Enforce 0600 on private.
	•	rsa encrypt --pub DataSpec --in DataSpec [--pad {oaep,pkcs1v15}] [--hash sha256]
	•	rsa decrypt --key DataSpec [same padding flags] --in DataSpec
	•	rsa sign --key DataSpec --msg DataSpec [--pad pss|pkcs1v15] [--hash sha256]
	•	rsa verify --pub DataSpec --msg DataSpec --sig DataSpec [same flags]
	•	Outputs:
	•	encrypt → ciphertext (blob)
	•	sign → signature (blob)
	•	verify → prints ok/fail; exit 0/2

6) dsa and dh

Small note: “DSA” is for signing; shared-secret is “DH/EC Diffie-Hellman.” I’ll split them:
	•	dsa: dsa new|sign|verify (mirrors rsa but --alg dsa1024/2048 etc.)
	•	dh (if you meant “shared”):
	•	dh shared --priv DataSpec --peer DataSpec [--group {ffdhe2048,…}|--curve x25519|secp256r1]
	•	Output: shared secret bytes (blob). Often you’ll immediately feed this to HKDF; consider --kdf … --bytes N that outputs a KDF’d key instead of raw shared secret.

7) bid

Ambiguous name. Two likely meanings: blind signatures (e.g., RSA-blind for anonymous credentials) or binary ID/address generator. I’ll make it a namespace you can fill later; the interface below works for blind signatures:
	•	bid new --alg rsa --bits N → issuer keys (like rsa new)
	•	bid sign --key DataSpec --msg DataSpec --blind → blind signature flow (you may need a --token DataSpec and a --context str:…)
	•	bid verify --pub DataSpec --msg DataSpec --sig DataSpec
If that’s not what you meant, keep the namespace and plug the real semantics in; the IO pattern (DataSpec in, blob/json out) still fits.

8) sss (Shamir’s Secret Sharing)
	•	Subcommands:
	•	sss new --secret DataSpec --threshold K --shares N [--id str:label]
	•	Output:
	•	--out-prefix PREFIX → writes PREFIX.1, PREFIX.2, … each a compact share file (recommend binary with header; also allow --armor for base64)
	•	--out-json → {"k":K,"n":N,"id":"…","shares":[{"i":1,"b64":"…"}, …]}
	•	sss shares --in @PREFIX.* (or many --in) → prints metadata / validity (handy for audits)
	•	sss recover --in @s1 --in @s2 ... (≥K files or b64: specs)
	•	Output: recovered secret (blob)

⸻

Examples (quick)

# isprime
tool isprime --n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF --rounds 64 --out-json

# random
tool rand bytes --bytes 32 --out-b64
tool rand int --bits 128             # decimal
tool rand int --bits 128 --out-hex   # hex
tool rand prime --bits 256 --safe --out-hex

# hash
tool hash --alg sha256 --msg @file.bin --out-hex

# aes
tool aes new --size 256 --out @key.bin
tool aes encrypt --mode gcm --key @key.bin --in @plain.bin --aad str:invoice-2025 --out-json
tool aes decrypt --key @key.bin --in @cipher.json --out @plain.bin

# rsa
tool rsa new --bits 3072 --out-prefix ~/.keys/alice
tool rsa sign --key @~/.keys/alice.key --msg @doc.pdf --pad pss --hash sha256 --out-b64
tool rsa verify --pub @~/.keys/alice.pub --msg @doc.pdf --sig b64:ABCD…

# dh (shared)
tool dh shared --curve x25519 --priv @me.key --peer @peer.pub --out-b64
tool dh shared --curve x25519 --priv @me.key --peer @peer.pub --kdf hkdf-sha256 --bytes 32 --out-b64

# sss
tool sss new --secret @master.key --threshold 3 --shares 5 --out-prefix ./vault/share
tool sss recover --in @vault/share.1 --in @vault/share.3 --in @vault/share.4 --out @master.key


⸻

argparse scaffold (drop-in)

def add_shared_output(parent):
  g = parent.add_mutually_exclusive_group()
  g.add_argument('--out-raw', dest='out_raw', action='store_true')
  g.add_argument('--out-hex', dest='out_hex', action='store_true')
  g.add_argument('--out-b64', dest='out_b64', action='store_true')
  g.add_argument('--out-json', dest='out_json', action='store_true')
  parent.add_argument('--pretty', action='store_true')
  parent.add_argument('--out', default='-')
  parent.add_argument('--out-prefix')
  parent.add_argument('--force', action='store_true')

def build_parser():
  p = argparse.ArgumentParser(prog='tool', description='Crypto toolbox')
  p.add_argument('--quiet', action='store_true')
  p.add_argument('--verbose', action='store_true')

  sub = p.add_subparsers(dest='cmd', required=True)

  # isprime
  p_ip = sub.add_parser('isprime', help='primality test')
  add_shared_output(p_ip)
  p_ip.add_argument('--n', required=True, help='integer (dec or 0x…)')
  p_ip.add_argument('--rounds', type=int, default=40)
  p_ip.add_argument('--expect', choices=['prime','composite'])
  p_ip.set_defaults(func=cmd_isprime)

  # rand
  p_rand = sub.add_parser('rand', help='randomness utilities')
  subr = p_rand.add_subparsers(dest='sub', required=True)

  pr_bytes = subr.add_parser('bytes', help='random bytes')
  add_shared_output(pr_bytes)
  pr_bytes.add_argument('--bytes', required=True)
  pr_bytes.set_defaults(func=cmd_rand_bytes)

  pr_int = subr.add_parser('int', help='random integer')
  add_shared_output(pr_int)
  pr_int.add_argument('--bits', required=True)
  pr_int.set_defaults(func=cmd_rand_int)

  pr_bits = subr.add_parser('bits', help='random bitstring')
  add_shared_output(pr_bits)
  pr_bits.add_argument('--bits', required=True)
  pr_bits.set_defaults(func=cmd_rand_bits)

  pr_prime = subr.add_parser('prime', help='random prime')
  add_shared_output(pr_prime)
  pr_prime.add_argument('--bits', required=True)
  pr_prime.add_argument('--safe', action='store_true')
  pr_prime.set_defaults(func=cmd_rand_prime)

  # hash
  p_hash = sub.add_parser('hash', help='hash a message')
  add_shared_output(p_hash)
  p_hash.add_argument('--alg', required=True, choices=['sha256','sha512','blake2b'])
  p_hash.add_argument('--msg', required=True, help='DataSpec')
  p_hash.set_defaults(func=cmd_hash)

  # aes
  p_aes = sub.add_parser('aes', help='AES operations')
  sub_aes = p_aes.add_subparsers(dest='sub', required=True)

  aes_new = sub_aes.add_parser('new', help='generate random AES key')
  add_shared_output(aes_new)
  aes_new.add_argument('--size', type=int, choices=[128,192,256], required=True)
  aes_new.set_defaults(func=cmd_aes_new)

  aes_frompass = sub_aes.add_parser('frompass', help='derive AES key from password')
  add_shared_output(aes_frompass)
  aes_frompass.add_argument('--from-pass', required=True, help='str:… or DataSpec')
  aes_frompass.add_argument('--kdf', choices=['argon2id','pbkdf2'], default='argon2id')
  aes_frompass.add_argument('--salt', help='DataSpec')
  aes_frompass.add_argument('--iters', type=int)
  aes_frompass.add_argument('--mem-mb', type=int)
  aes_frompass.add_argument('--parallelism', type=int)
  aes_frompass.add_argument('--size', type=int, choices=[128,192,256], required=True)
  aes_frompass.set_defaults(func=cmd_aes_frompass)

  def add_aes_io(sp):
    add_shared_output(sp)
    sp.add_argument('--in', dest='inp', required=True, help='DataSpec')
    sp.add_argument('--mode', choices=['gcm','ctr','cbc'], default='gcm')
    sp.add_argument('--key', help='DataSpec')
    sp.add_argument('--from-pass', help='str:… or DataSpec')
    sp.add_argument('--kdf', choices=['argon2id','pbkdf2'])
    sp.add_argument('--salt', help='DataSpec')
    sp.add_argument('--iters', type=int)
    sp.add_argument('--iv', '--nonce', dest='nonce', help='DataSpec')
    sp.add_argument('--aad', help='DataSpec')

  aes_enc = sub_aes.add_parser('encrypt', help='encrypt data')
  add_aes_io(aes_enc)
  aes_enc.set_defaults(func=cmd_aes_encrypt)

  aes_dec = sub_aes.add_parser('decrypt', help='decrypt data')
  add_aes_io(aes_dec)
  aes_dec.add_argument('--in-format', choices=['auto','json','raw'], default='auto')
  aes_dec.set_defaults(func=cmd_aes_decrypt)

  # rsa
  p_rsa = sub.add_parser('rsa', help='RSA operations')
  sr = p_rsa.add_subparsers(dest='sub', required=True)

  rsa_new = sr.add_parser('new', help='generate RSA keypair')
  add_shared_output(rsa_new)
  rsa_new.add_argument('--bits', type=int, required=True)
  rsa_new.add_argument('--e', type=int, default=65537)
  rsa_new.set_defaults(func=cmd_rsa_new)

  def add_rsa_keying(sp, need_pub=False, need_priv=False):
    add_shared_output(sp)
    if need_pub:
      sp.add_argument('--pub', required=True, help='DataSpec')
    if need_priv:
      sp.add_argument('--key', required=True, help='DataSpec')
    sp.add_argument('--pad', choices=['oaep','pkcs1v15'], default='oaep')
    sp.add_argument('--hash', choices=['sha256','sha512'], default='sha256')

  rsa_enc = sr.add_parser('encrypt', help='RSA encrypt')
  add_rsa_keying(rsa_enc, need_pub=True)
  rsa_enc.add_argument('--in', dest='inp', required=True, help='DataSpec')
  rsa_enc.set_defaults(func=cmd_rsa_encrypt)

  rsa_dec = sr.add_parser('decrypt', help='RSA decrypt')
  add_rsa_keying(rsa_dec, need_priv=True)
  rsa_dec.add_argument('--in', dest='inp', required=True, help='DataSpec')
  rsa_dec.set_defaults(func=cmd_rsa_decrypt)

  rsa_sign = sr.add_parser('sign', help='RSA sign')
  add_shared_output(rsa_sign)
  rsa_sign.add_argument('--key', required=True, help='DataSpec')
  rsa_sign.add_argument('--msg', required=True, help='DataSpec')
  rsa_sign.add_argument('--pad', choices=['pss','pkcs1v15'], default='pss')
  rsa_sign.add_argument('--hash', choices=['sha256','sha512'], default='sha256')
  rsa_sign.set_defaults(func=cmd_rsa_sign)

  rsa_verify = sr.add_parser('verify', help='RSA verify')
  add_shared_output(rsa_verify)
  rsa_verify.add_argument('--pub', required=True, help='DataSpec')
  rsa_verify.add_argument('--msg', required=True, help='DataSpec')
  rsa_verify.add_argument('--sig', required=True, help='DataSpec')
  rsa_verify.add_argument('--pad', choices=['pss','pkcs1v15'], default='pss')
  rsa_verify.add_argument('--hash', choices=['sha256','sha512'], default='sha256')
  rsa_verify.set_defaults(func=cmd_rsa_verify)

  # dsa
  p_dsa = sub.add_parser('dsa', help='DSA signing')
  sd = p_dsa.add_subparsers(dest='sub', required=True)
  dsa_new = sd.add_parser('new', help='DSA keypair'); add_shared_output(dsa_new)
  dsa_new.add_argument('--bits', type=int, required=True); dsa_new.set_defaults(func=cmd_dsa_new)
  dsa_sign = sd.add_parser('sign', help='DSA sign'); add_shared_output(dsa_sign)
  dsa_sign.add_argument('--key', required=True); dsa_sign.add_argument('--msg', required=True)
  dsa_sign.set_defaults(func=cmd_dsa_sign)
  dsa_verify = sd.add_parser('verify', help='DSA verify'); add_shared_output(dsa_verify)
  dsa_verify.add_argument('--pub', required=True); dsa_verify.add_argument('--msg', required=True); dsa_verify.add_argument('--sig', required=True)
  dsa_verify.set_defaults(func=cmd_dsa_verify)

  # dh (shared secret)
  p_dh = sub.add_parser('dh', help='Diffie-Hellman key agreement')
  sdh = p_dh.add_subparsers(dest='sub', required=True)
  dh_shared = sdh.add_parser('shared', help='compute shared secret'); add_shared_output(dh_shared)
  dh_shared.add_argument('--priv', required=True); dh_shared.add_argument('--peer', required=True)
  dh_shared.add_argument('--group', help='ffdhe… or secp…'); dh_shared.add_argument('--curve', help='x25519, secp256r1, …')
  dh_shared.add_argument('--kdf', choices=['none','hkdf-sha256','hkdf-sha512'], default='none')
  dh_shared.add_argument('--bytes', type=int)
  dh_shared.set_defaults(func=cmd_dh_shared)

  # bid (placeholder)
  p_bid = sub.add_parser('bid', help='blind-id namespace'); sbid = p_bid.add_subparsers(dest='sub', required=True)
  bid_new = sbid.add_parser('new', help='issuer keys'); add_shared_output(bid_new); bid_new.set_defaults(func=cmd_bid_new)
  bid_verify = sbid.add_parser('verify', help='verify token'); add_shared_output(bid_verify)
  bid_verify.add_argument('--pub', required=True); bid_verify.add_argument('--msg', required=True); bid_verify.add_argument('--sig', required=True)
  bid_verify.set_defaults(func=cmd_bid_verify)

  # sss
  p_sss = sub.add_parser('sss', help='Shamir secret sharing'); ssss = p_sss.add_subparsers(dest='sub', required=True)
  sss_new = ssss.add_parser('new', help='split secret'); add_shared_output(sss_new)
  sss_new.add_argument('--secret', required=True); sss_new.add_argument('--threshold', type=int, required=True); sss_new.add_argument('--shares', type=int, required=True); sss_new.add_argument('--id')
  sss_new.set_defaults(func=cmd_sss_new)
  sss_shares = ssss.add_parser('shares', help='inspect shares'); add_shared_output(sss_shares)
  sss_shares.add_argument('--in', dest='inputs', action='append', required=True)
  sss_shares.set_defaults(func=cmd_sss_shares)
  sss_rec = ssss.add_parser('recover', help='recover secret'); add_shared_output(sss_rec)
  sss_rec.add_argument('--in', dest='inputs', action='append', required=True)
  sss_rec.set_defaults(func=cmd_sss_recover)

  return p


⸻

If you want, I can fill in concrete implementations next (e.g., Miller–Rabin for isprime, X25519 for dh shared, AES-GCM JSON bundle, RSA PSS, SSS split/recover). Tell me which two or three you want first and I’ll wire them up.

"""

from __future__ import annotations

import argparse
import logging
# import pdb
import sys

from . import base

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


def _BuildParser() -> argparse.ArgumentParser:  # pylint: disable=too-many-statements,too-many-locals
  """Construct the CLI argument parser (kept in sync with the docs)."""
  # ========================= main parser ==========================================================
  parser: argparse.ArgumentParser = argparse.ArgumentParser(
      prog='poetry run safetrans',
      description=('safetrans: CLI for safe random, primes, hashing, '
                   'AES, RSA, DSA, bidding, and secret sharing.'),
      epilog=(
          'Examples:\n\n'
          '  # --- Randomness / Primes ---\n'
          '  poetry run transcrypto random bits 16\n'
          '  poetry run transcrypto random bytes 32\n'
          '  poetry run transcrypto random int 1000 2000\n'
          '  poetry run transcrypto random prime 64\n\n'
          '  poetry run transcrypto isprime 428568761\n'
          '  # --- Hashing ---\n'
          '  poetry run transcrypto hash sha256 xyz\n'
          '  poetry run transcrypto --b64 hash sha512 -- eHl6\n'
          '  poetry run transcrypto hash file /etc/passwd --digest sha512\n\n'
          '  # --- AES ---\n'
          '  poetry run transcrypto --out-b64 aes new\n'
          '  poetry run transcrypto --out-b64 aes key "correct horse battery staple"\n'
          '  poetry run transcrypto --b64 --out-b64 aes encrypt -k "<b64key>" -- "secret"\n'
          '  poetry run transcrypto --b64 --out-b64 aes decrypt -k "<b64key>" -- "<ciphertext>"\n'
          '  # --- RSA ---\n'
          '  poetry run transcrypto -p rsa-key rsa new --bits 2048\n'
          '  poetry run transcrypto --bin --out-b64 -p rsa-key.pub rsa encrypt -a <aad> <plaintext>\n'
          '  poetry run transcrypto --b64 --out-bin -p rsa-key.priv rsa decrypt -a <aad> -- <ciphertext>\n'
          '  poetry run transcrypto --bin --out-b64 -p rsa-key.priv rsa sign <message>\n'
          '  poetry run transcrypto --b64 -p rsa-key.pub rsa verify -- <message> <signature>\n\n'
          '  # --- DSA ---\n'
          '  poetry run transcrypto -p dsa-key dsa shared --p-bits 2048 --q-bits 256\n'
          '  poetry run transcrypto -p dsa-key dsa new\n'
          '  poetry run transcrypto --bin --out-b64 -p dsa-key.priv dsa sign <message>\n'
          '  poetry run transcrypto --b64 -p dsa-key.pub dsa verify -- <message> <signature>\n\n'
          '  # --- Public Bid ---\n'
          '  poetry run transcrypto --bin bid new "tomorrow it will rain"\n'
          '  poetry run transcrypto --out-bin bid verify\n\n'
          '  # --- Shamir Secret Sharing (SSS) ---\n'
          '  poetry run transcrypto -p sss-key sss new 3 --bits 1024\n'
          '  poetry run transcrypto --bin -p sss-key sss shares <secret> <n>\n'
          '  poetry run transcrypto --out-bin -p sss-key sss recover\n'
      ),
      formatter_class=argparse.RawTextHelpFormatter)
  sub = parser.add_subparsers(dest='command')

  # ========================= global flags =========================================================
  # -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG
  parser.add_argument(
      '-v', '--verbose', action='count', default=0,
      help='Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG)')

  parser.add_argument(
      '-i', '--in', type=str, default='',
      help=('Input: "int" is (decimal) integer, "hex" is hexadecimal, '
            '"b64" is base-64 encoded, "bin" is binary, '
            'anything else is considered a "/file/path" or "/file/path/prefix" to be used to '
            'read binary objects; '
            'default is intentionally empty because each command will explain what default '
            'behavior it will use, eg. for `random int` the default is decimal int but '
            'for `rsa encrypt` the default is to expect a file prefix'))

  parser.add_argument(
      '-o', '--out', type=str, default='',
      help=('Output: "int" is (decimal) integer, "hex" is hexadecimal, '
            '"b64" is base-64 encoded, "bin" is binary, '
            'anything else is considered a "/file/path" or "/file/path/prefix" to be used to '
            'output binary objects; '
            'default is intentionally empty because each command will explain what default '
            'behavior it will use, eg. for `random int` the default is hexadecimal but '
            'for `rsa new` the default is to expect a file prefix'))

  # # --hex/--b64/--bin for input mode (default hex)
  # in_grp = parser.add_mutually_exclusive_group()
  # in_grp.add_argument('--hex', action='store_true', help='Treat inputs as hex string (default)')
  # in_grp.add_argument(
  #     '--b64', action='store_true',
  #     help=('Treat inputs as base64url; sometimes base64 will start with "-" and that can '
  #           'conflict with flags, so use "--" before positional args if needed'))
  # in_grp.add_argument('--bin', action='store_true', help='Treat inputs as binary (bytes)')

  # # --out-hex/--out-b64/--out-bin for output mode (default hex)
  # out_grp = parser.add_mutually_exclusive_group()
  # out_grp.add_argument('--out-hex', action='store_true', help='Outputs as hex (default)')
  # out_grp.add_argument('--out-b64', action='store_true', help='Outputs as base64url')
  # out_grp.add_argument('--out-bin', action='store_true', help='Outputs as binary (bytes)')

  # # key loading/saving from/to file, with optional password; will only work with some commands
  # parser.add_argument(
  #     '-p', '--key-path', type=str, default='',
  #     help='File path to serialized key object, if key is needed for operation')
  # parser.add_argument(
  #     '--protect', type=str, default='',
  #     help='Password to encrypt/decrypt key file if using the `-p`/`--key-path` option')

  # ========================= randomness / primes ==================================================

  # Cryptographically secure randomness
  p_rand: argparse.ArgumentParser = sub.add_parser(
      'random', help='Cryptographically secure randomness, from the OS CSPRNG.')
  rsub = p_rand.add_subparsers(dest='rand_command')

  # Random bits
  p_rand_bits: argparse.ArgumentParser = rsub.add_parser(
      'bits',
      help=('Random bytes with exact bit length `bits` (≥ 8, MSB will be 1). '
            'By default, `-o/--out` is hexadecimal.'),
      epilog='random bits 16\n36650')##
  p_rand_bits.add_argument('bits', type=int, help='Number of bits to generate, ≥ 8')

  # Random bytes
  p_rand_bytes: argparse.ArgumentParser = rsub.add_parser(
      'bytes',
      help=('Random bytes with exact bit length `n` (≥ 1, MSB will be 1). '
            'By default, `-o/--out` is hexadecimal.'),
      epilog='random bytes 32\n6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f')##
  p_rand_bytes.add_argument('n', type=int, help='Number of bytes to generate, ≥ 1')

  # Random integer in [min, max]
  p_rand_int: argparse.ArgumentParser = rsub.add_parser(
      'int',
      help=('Uniform random integer in `[min, max]` range, inclusive. '
            'By default, `-o/--out` is hexadecimal.'),
      epilog='random int 1000 2000\n1628')
  p_rand_int.add_argument('min', type=str, help='Minimum, ≥ 0')
  p_rand_int.add_argument('max', type=str, help='Maximum, > `min`')

  # Random prime with given bit length
  p_rand_prime: argparse.ArgumentParser = rsub.add_parser(
      'prime',
      help=('Random prime with exact bit length `bits` (≥ 11, MSB will be 1). '
            'By default, `-o/--out` is hexadecimal.'),
      epilog='random prime 32\n2365910551')##
  p_rand_prime.add_argument('bits', type=int, help='Number of bits to generate, ≥ 11')

  # Primality test with safe defaults
  p_isprime: argparse.ArgumentParser = sub.add_parser(
      'isprime',
      help='Primality test with safe defaults, useful for any integer size.',
      epilog='isprime 2305843009213693951\nTrue $$ isprime 2305843009213693953\nFalse')
  p_isprime.add_argument(
      'n', type=str, help='Integer to test, ≥ 1')

  # ========================= hashing ==============================================================

  # Hashing group
  p_hash: argparse.ArgumentParser = sub.add_parser(
      'hash', help='Cryptographic Hashing (SHA-256 / SHA-512 / file).')
  hash_sub = p_hash.add_subparsers(dest='hash_command')

  # SHA-256
  p_h256: argparse.ArgumentParser = hash_sub.add_parser(
      'sha256',
      help='SHA-256 of input `data`.',
      epilog=('--bin hash sha256 xyz\n'
              '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282 $$'
              '--b64 hash sha256 -- eHl6  # "xyz" in base-64\n'
              '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282'))
  p_h256.add_argument('data', type=str, help='Input data (raw text; or use --hex/--b64/--bin)')

  # SHA-512
  p_h512 = hash_sub.add_parser(
      'sha512',
      help='SHA-512 of input `data`.',
      epilog=('--bin hash sha512 xyz\n'
              '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
              '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728 $$'
              '--b64 hash sha512 -- eHl6  # "xyz" in base-64\n'
              '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
              '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728'))
  p_h512.add_argument('data', type=str, help='Input data (raw text; or use --hex/--b64/--bin)')

  # Hash file contents (streamed)
  p_hf: argparse.ArgumentParser = hash_sub.add_parser(
      'file',
      help='SHA-256/512 hash of file contents, defaulting to SHA-256.',
      epilog=('hash file /etc/passwd --digest sha512\n'
              '8966f5953e79f55dfe34d3dc5b160ac4a4a3f9cbd1c36695a54e28d77c7874df'
              'f8595502f8a420608911b87d336d9e83c890f0e7ec11a76cb10b03e757f78aea'))
  p_hf.add_argument('path', type=str, help='Path to existing file')
  p_hf.add_argument('--digest', choices=['sha256', 'sha512'], default='sha256',
                    help='Digest type, SHA-256 ("sha256") or SHA-512 ("sha512")')

  # ========================= AES (GCM + ECB helper) ===============================================

  # AES group
  p_aes: argparse.ArgumentParser = sub.add_parser(
      'aes',
      help=('AES-256 operations (GCM/ECB) and key derivation. '
            'No measures are taken here to prevent timing attacks.'))
  aes_sub = p_aes.add_subparsers(dest='aes_command')

  # Derive key from password
  p_aes_key_new: argparse.ArgumentParser = aes_sub.add_parser(
      'key',
      help=('Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive '
            'salt and iterations. Very good/safe for simple password-to-key but not for '
            'passwords databases (because of constant salt).'),
      epilog=('--out-b64 aes key "correct horse battery staple"\n'
              'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= $$ '  # cspell:disable-line
              '-p keyfile.out --protect hunter aes key "correct horse battery staple"\n'
              'AES key saved to \'keyfile.out\''))
  p_aes_key_new.add_argument(
      'password', type=str, help='Password (leading/trailing spaces ignored)')

  # Derive key from password
  p_aes_key_pass: argparse.ArgumentParser = aes_sub.add_parser(
      'new',
      help=('Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive '
            'salt and iterations. Very good/safe for simple password-to-key but not for '
            'passwords databases (because of constant salt).'),
      epilog=('--out-b64 aes key "correct horse battery staple"\n'
              'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= $$ '  # cspell:disable-line
              '-p keyfile.out --protect hunter aes key "correct horse battery staple"\n'
              'AES key saved to \'keyfile.out\''))
  p_aes_key_pass.add_argument(
      'password', type=str, help='Password (leading/trailing spaces ignored)')

  # AES-256-GCM encrypt
  p_aes_enc: argparse.ArgumentParser = aes_sub.add_parser(
      'encrypt',
      help=('AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with '
            '`-p`/`--key-path` keyfile. All inputs are raw, or you '
            'can use `--bin`/`--hex`/`--b64` flags. Attention: if you provide `-a`/`--aad` '
            '(associated data, AAD), you will need to provide the same AAD when decrypting '
            'and it is NOT included in the `ciphertext`/CT returned by this method!'),
      epilog=('--b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- '       # cspell:disable-line
              'AAAAAAB4eXo=\nF2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA== $$ '            # cspell:disable-line
              '--b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 '  # cspell:disable-line
              '-- AAAAAAB4eXo=\nxOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA=='))           # cspell:disable-line
  p_aes_enc.add_argument('plaintext', type=str, help='Input data to encrypt (PT)')
  p_aes_enc.add_argument(
      '-k', '--key', type=str, default='', help='Key if `-p`/`--key-path` wasn\'t used (32 bytes)')
  p_aes_enc.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be separately sent to receiver/stored)')

  # AES-256-GCM decrypt
  p_aes_dec: argparse.ArgumentParser = aes_sub.add_parser(
      'decrypt',
      help=('AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with '
            '`-p`/`--key-path` keyfile. All inputs are raw, or you '
            'can use `--bin`/`--hex`/`--b64` flags. Attention: if you provided `-a`/`--aad` '
            '(associated data, AAD) during encryption, you will need to provide the same AAD now!'),
      epilog=('--b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- '      # cspell:disable-line
              'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\nAAAAAAB4eXo= $$ '           # cspell:disable-line
              '--b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= '         # cspell:disable-line
              '-a eHl6 -- xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==\nAAAAAAB4eXo='))  # cspell:disable-line
  p_aes_dec.add_argument('ciphertext', type=str, help='Input data to decrypt (CT)')
  p_aes_dec.add_argument(
      '-k', '--key', type=str, default='', help='Key if `-p`/`--key-path` wasn\'t used (32 bytes)')
  p_aes_dec.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be exactly the same as used during encryption)')

  # ========================= RSA ==================================================================

  # RSA group
  p_rsa: argparse.ArgumentParser = sub.add_parser(
      'rsa',
      help=('RSA (Rivest-Shamir-Adleman) asymmetric cryptography. '
            'No measures are taken here to prevent timing attacks. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  rsa_sub = p_rsa.add_subparsers(dest='rsa_command')

  # Generate new RSA private key
  p_rsa_new: argparse.ArgumentParser = rsa_sub.add_parser(
      'new',
      help=('Generate RSA private/public key pair with `bits` modulus size '
            '(prime sizes will be `bits`/2). '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('-p rsa-key rsa new --bits 64  # NEVER use such a small key: example only!\n'
              'RSA private/public keys saved to \'rsa-key.priv/.pub\''))
  p_rsa_new.add_argument(
      '--bits', type=int, default=3332, help='Modulus size in bits; the default is a safe size')

  # Encrypt with public key
  p_rsa_enc_safe: argparse.ArgumentParser = rsa_sub.add_parser(
      'encrypt',
      help='Encrypt `message` with public key.',
      epilog=('--bin --out-b64 -p rsa-key.pub rsa encrypt "abcde" -a "xyz"\n'
              'AO6knI6xwq6TGR…Qy22jiFhXi1eQ=='))
  p_rsa_enc_safe.add_argument('plaintext', type=str, help='Message to encrypt')
  p_rsa_enc_safe.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be separately sent to receiver/stored)')

  # Decrypt ciphertext with private key
  p_rsa_dec_safe: argparse.ArgumentParser = rsa_sub.add_parser(
      'decrypt',
      help='Decrypt `ciphertext` with private key.',
      epilog=('--b64 --out-bin -p rsa-key.priv rsa decrypt -a eHl6 -- '
              'AO6knI6xwq6TGR…Qy22jiFhXi1eQ==\nabcde'))
  p_rsa_dec_safe.add_argument('ciphertext', type=str, help='Ciphertext to decrypt')
  p_rsa_dec_safe.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be exactly the same as used during encryption)')

  # Sign message with private key
  p_rsa_sig_safe: argparse.ArgumentParser = rsa_sub.add_parser(
      'sign',
      help='Sign `message` with private key.',
      epilog='--bin --out-b64 -p rsa-key.priv rsa sign "xyz"\n91TS7gC6LORiL…6RD23Aejsfxlw==')  # cspell:disable-line
  p_rsa_sig_safe.add_argument('message', type=str, help='Message to sign')
  p_rsa_sig_safe.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be separately sent to receiver/stored)')

  # Verify signature with public key
  p_rsa_ver_safe: argparse.ArgumentParser = rsa_sub.add_parser(
      'verify',
      help='Verify `signature` for `message` with public key.',
      epilog=('--b64 -p rsa-key.pub rsa verify -- eHl6 '
              '91TS7gC6LORiL…6RD23Aejsfxlw==\nRSA signature: OK $$ '     # cspell:disable-line
              '--b64 -p rsa-key.pub rsa verify -- eLl6 '
              '91TS7gC6LORiL…6RD23Aejsfxlw==\nRSA signature: INVALID'))  # cspell:disable-line
  p_rsa_ver_safe.add_argument('message', type=str, help='Message that was signed earlier')
  p_rsa_ver_safe.add_argument('signature', type=str, help='Putative signature for `message`')
  p_rsa_ver_safe.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be exactly the same as used during signing)')

  # ========================= DSA ==================================================================

  # DSA group
  p_dsa: argparse.ArgumentParser = sub.add_parser(
      'dsa',
      help=('DSA (Digital Signature Algorithm) asymmetric signing/verifying. '
            'No measures are taken here to prevent timing attacks. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  dsa_sub = p_dsa.add_subparsers(dest='dsa_command')

  # Generate shared (p,q,g) params
  p_dsa_shared: argparse.ArgumentParser = dsa_sub.add_parser(
      'shared',
      help=('Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is '
            'the first step in key generation. `q-bits` should be larger than the secrets that '
            'will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). '
            'The shared key can safely be used by any number of users to generate their '
            'private/public key pairs (with the `new` command). The shared keys are "public". '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('-p dsa-key dsa shared --p-bits 128 --q-bits 32  '
              '# NEVER use such a small key: example only!\n'
              'DSA shared key saved to \'dsa-key.shared\''))
  p_dsa_shared.add_argument(
      '--p-bits', type=int, default=4096,
      help='Prime modulus (`p`) size in bits; the default is a safe size')
  p_dsa_shared.add_argument(
      '--q-bits', type=int, default=544,
      help=('Prime modulus (`q`) size in bits; the default is a safe size ***IFF*** you '
            'are protecting symmetric keys or regular hashes'))

  # Generate individual private key from shared (p,q,g)
  dsa_sub.add_parser(
      'new',
      help='Generate an individual DSA private/public key pair from a shared key.',
      epilog='-p dsa-key dsa new\nDSA private/public keys saved to \'dsa-key.priv/.pub\'')

  # Sign message with private key
  p_dsa_sign_safe: argparse.ArgumentParser = dsa_sub.add_parser(
      'sign',
      help='Sign message with private key.',
      epilog='--bin --out-b64 -p dsa-key.priv dsa sign "xyz"\nyq8InJVpViXh9…BD4par2XuA=')
  p_dsa_sign_safe.add_argument('message', type=str, help='Message to sign')
  p_dsa_sign_safe.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be separately sent to receiver/stored)')

  # Verify DSA signature (s1,s2)
  p_dsa_verify_safe: argparse.ArgumentParser = dsa_sub.add_parser(
      'verify',
      help='Verify `signature` for `message` with public key.',
      epilog=('--b64 -p dsa-key.pub dsa verify -- eHl6 yq8InJVpViXh9…BD4par2XuA=\n'
              'DSA signature: OK $$ '
              '--b64 -p dsa-key.pub dsa verify -- eLl6 yq8InJVpViXh9…BD4par2XuA=\n'
              'DSA signature: INVALID'))
  p_dsa_verify_safe.add_argument('message', type=str, help='Message that was signed earlier')
  p_dsa_verify_safe.add_argument('signature', type=str, help='Putative signature for `message`')
  p_dsa_verify_safe.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be exactly the same as used during signing)')

  # ========================= Public Bid ===========================================================

  # bidding group
  p_bid: argparse.ArgumentParser = sub.add_parser(
      'bid',
      help=('Bidding on a `secret` so that you can cryptographically convince a neutral '
            'party that the `secret` that was committed to previously was not changed. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  bid_sub = p_bid.add_subparsers(dest='bid_command')

  # Generate a new bid
  p_bid_new: argparse.ArgumentParser = bid_sub.add_parser(
      'new',
      help=('Generate the bid files for `secret`. '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('--bin -p my-bid bid new "tomorrow it will rain"\n'
              'Bid private/public commitments saved to \'my-bid.priv/.pub\''))
  p_bid_new.add_argument('secret', type=str, help='Input data to bid to, the protected "secret"')

  # verify bid
  bid_sub.add_parser(
      'verify',
      help=('Verify the bid files for correctness and reveal the `secret`. '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('--out-bin -p my-bid bid verify\n'
              'Bid commitment: OK\nBid secret:\ntomorrow it will rain'))

  # ========================= Shamir Secret Sharing ================================================

  # SSS group
  p_sss: argparse.ArgumentParser = sub.add_parser(
      'sss',
      help=('SSS (Shamir Shared Secret) secret sharing crypto scheme. '
            'No measures are taken here to prevent timing attacks. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  sss_sub = p_sss.add_subparsers(dest='sss_command')

  # Generate new SSS params (t, prime, coefficients)
  p_sss_new: argparse.ArgumentParser = sss_sub.add_parser(
      'new',
      help=('Generate the private keys with `bits` prime modulus size and so that at least a '
            '`minimum` number of shares are needed to recover the secret. '
            'This key will be used to generate the shares later (with the `shares` command). '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('-p sss-key sss new 3 --bits 64  # NEVER use such a small key: example only!\n'
              'SSS private/public keys saved to \'sss-key.priv/.pub\''))
  p_sss_new.add_argument(
      'minimum', type=int, help='Minimum number of shares required to recover secret, ≥ 2')
  p_sss_new.add_argument(
      '--bits', type=int, default=1024,
      help=('Prime modulus (`p`) size in bits; the default is a safe size ***IFF*** you '
            'are protecting symmetric keys; the number of bits should be comfortably larger '
            'than the size of the secret you want to protect with this scheme'))

  # Issue N shares for a secret
  p_sss_shares_safe: argparse.ArgumentParser = sss_sub.add_parser(
      'shares',
      help='Shares: Issue `count` private shares for a `secret`.',
      epilog=('--bin -p sss-key sss shares "abcde" 5\n'
              'SSS 5 individual (private) shares saved to \'sss-key.share.1…5\'\n'
              '$ rm sss-key.share.2 sss-key.share.4  '
              '# this is to simulate only having shares 1,3,5'))
  p_sss_shares_safe.add_argument('secret', type=str, help='Secret to be protected')
  p_sss_shares_safe.add_argument(
      'count', type=int,
      help=('How many shares to produce; must be ≥ `minimum` used in `new` command or else the '
            '`secret` would become unrecoverable'))

  # Recover secret from shares
  sss_sub.add_parser(
      'recover',
      help='Recover secret from shares; will use any available shares that were found.',
      epilog=('--out-bin -p sss-key sss recover\n'
              'Loaded SSS share: \'sss-key.share.3\'\n'
              'Loaded SSS share: \'sss-key.share.5\'\n'
              'Loaded SSS share: \'sss-key.share.1\'  '
              '# using only 3 shares: number 2/4 are missing\n'
              'Secret:\nabcde'))

  # ========================= Markdown Generation ==================================================

  # Documentation generation
  doc: argparse.ArgumentParser = sub.add_parser(
      'doc', help='Documentation utilities. (Not for regular use: these are developer utils.)')
  doc_sub = doc.add_subparsers(dest='doc_command')
  doc_sub.add_parser(
      'md',
      help='Emit Markdown docs for the CLI (see README.md section "Creating a New Version").',
      epilog='doc md > transcrypto.md\n<<saves file>>')

  return parser


def main(argv: list[str] | None = None, /) -> int:  # pylint: disable=invalid-name,too-many-locals,too-many-branches,too-many-statements
  """Main entry point."""
  # build the parser and parse args
  parser: argparse.ArgumentParser = _BuildParser()
  args: argparse.Namespace = parser.parse_args(argv)
  # take care of global options
  levels: list[int] = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
  logging.basicConfig(
      level=levels[min(args.verbose, len(levels) - 1)],  # type: ignore
      format=getattr(base, 'LOG_FORMAT', '%(levelname)s:%(message)s'))
  logging.captureWarnings(True)

  try:
    # get the command, do basic checks and switch
    command: str = args.command.lower().strip() if args.command else ''
    match command:
      # -------- TODO ----------
      case 'TODO':
        pass

      # -------- Documentation ----------
      case 'doc':
        doc_command: str = (
            args.doc_command.lower().strip() if getattr(args, 'doc_command', '') else '')
        match doc_command:
          case 'md':
            print(base.GenerateCLIMarkdown(
                'safetrans', _BuildParser(), description=(
                    '`safetrans` is a command-line utility that provides ***safe*** crypto '
                    'primitives. It serves as a convenient wrapper over the Python APIs, '
                    'enabling only safe **cryptographic operations**, '
                    '**number theory functions**, **secure randomness generation**, **hashing**, '
                    '**AES**, **RSA**, **DSA**, **bidding**, **SSS**, '
                    'and other utilities without writing code.')))
          case _:
            raise NotImplementedError()

      case _:
        parser.print_help()

  except NotImplementedError as err:
    print(f'Invalid command: {err}')
  except (base.Error, ValueError) as err:
    print(str(err))

  return 0


if __name__ == '__main__':
  sys.exit(main())
