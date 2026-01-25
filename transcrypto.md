<!-- cspell:disable -->
<!-- auto-generated; DO NOT EDIT! see base.GenerateTyperHelpMarkdown() -->

# `transcrypto` Command-Line Interface

```text
Usage: transcrypto [OPTIONS] COMMAND [ARGS]...                                                                                                            
                                                                                                                                                           
 TransCrypto CLI: cryptographic operations and key management.                                                                                             
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --version                                                        Show version and exit.                                                                 │
│ --verbose             -v                INTEGER RANGE [0<=x<=3]  Verbosity (nothing=ERROR, -v=WARNING, -vv=INFO, -vvv=DEBUG).               │
│ --color                   --no-color                             Force enable/disable colored output (respects NO_COLOR env var if not provided).       │
│                                                                  Defaults to having colors.                                                             │
│ --input-format        -i                            How to parse inputs: hex (default), b64, or bin.                         │
│ --output-format       -o                            How to format outputs: hex (default), b64, or bin.                       │
│ --key-path            -p                PATH                     File path to serialized key object, if key is needed for operation                     │
│ --protect                               TEXT                     Password to encrypt/decrypt key file if using the `-p`/`--key-path` option             │
│ --install-completion                                             Install completion for the current shell.                                              │
│ --show-completion                                                Show completion for the current shell, to copy it or customize the installation.       │
│ --help                                                           Show this message and exit.                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ isprime    Primality test with safe defaults, useful for any integer size.                                                                              │
│ primegen   Generate (stream) primes ≥ `start` (prints a limited `count` by default).                                                                    │
│ mersenne   Generate (stream) Mersenne prime exponents `k`, also outputting `2^k-1` (the Mersenne prime, `M`) and `M×2^(k-1)` (the associated perfect    │
│            number), starting at `min-k` and stopping once `k` > `cutoff-k`.                                                                             │
│ gcd        Greatest Common Divisor (GCD) of integers `a` and `b`.                                                                                       │
│ xgcd       Extended Greatest Common Divisor (x-GCD) of integers `a` and `b`, will return `(g, x, y)` where `a×x+b×y==g`.                                │
│ markdown   Emit Markdown docs for the CLI (see README.md section "Creating a New Version").                                                             │
│ random     Cryptographically secure randomness, from the OS CSPRNG.                                                                                     │
│ mod        Modular arithmetic helpers.                                                                                                                  │
│ hash       Cryptographic Hashing (SHA-256 / SHA-512 / file).                                                                                            │
│ aes        AES-256 operations (GCM/ECB) and key derivation. No measures are taken here to prevent timing attacks.                                       │
│ rsa        RSA (Rivest-Shamir-Adleman) asymmetric cryptography. No measures are taken here to prevent timing attacks. All methods require file key(s)   │
│            as `-p`/`--key-path` (see provided examples).                                                                                                │
│ elgamal    El-Gamal asymmetric cryptography. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` │
│            (see provided examples).                                                                                                                     │
│ dsa        DSA (Digital Signature Algorithm) asymmetric signing/verifying. No measures are taken here to prevent timing attacks. All methods require    │
│            file key(s) as `-p`/`--key-path` (see provided examples).                                                                                    │
│ bid        Bidding on a `secret` so that you can cryptographically convince a neutral party that the `secret` that was committed to previously was not  │
│            changed. All methods require file key(s) as `-p`/`--key-path` (see provided examples).                                                       │
│ sss        SSS (Shamir Shared Secret) secret sharing crypto scheme. No measures are taken here to prevent timing attacks. All methods require file      │
│            key(s) as `-p`/`--key-path` (see provided examples).                                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 # --- Randomness ---                                                                                                                                      
 poetry run transcrypto random bits 16                                                                                                                     
 poetry run transcrypto random int 1000 2000                                                                                                               
 poetry run transcrypto random bytes 32                                                                                                                    
 poetry run transcrypto random prime 64                                                                                                                    
                                                                                                                                                           
 # --- Primes ---                                                                                                                                          
 poetry run transcrypto isprime 428568761                                                                                                                  
 poetry run transcrypto primegen 100 -c 3                                                                                                                  
 poetry run transcrypto mersenne -k 2 -C 17                                                                                                                
                                                                                                                                                           
 # --- Integer / Modular Math ---                                                                                                                          
 poetry run transcrypto gcd 462 1071                                                                                                                       
 poetry run transcrypto xgcd 127 13                                                                                                                        
 poetry run transcrypto mod inv 17 97                                                                                                                      
 poetry run transcrypto mod div 6 127 13                                                                                                                   
 poetry run transcrypto mod exp 438 234 127                                                                                                                
 poetry run transcrypto mod poly 12 17 10 20 30                                                                                                            
 poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1                                                                                                      
 poetry run transcrypto mod crt 6 7 127 13                                                                                                                 
                                                                                                                                                           
 # --- Hashing ---                                                                                                                                         
 poetry run transcrypto hash sha256 xyz                                                                                                                    
 poetry run transcrypto --input-format b64 hash sha512 -- eHl6                                                                                             
 poetry run transcrypto hash file /etc/passwd --digest sha512                                                                                              
                                                                                                                                                           
 # --- AES ---                                                                                                                                             
 poetry run transcrypto --output-format b64 aes key "correct horse battery staple"                                                                         
 poetry run transcrypto -i b64 -o b64 aes encrypt -k "<b64key>" -- "secret"                                                                                
 poetry run transcrypto -i b64 -o b64 aes decrypt -k "<b64key>" -- "<ciphertext>"                                                                          
 poetry run transcrypto aes ecb -k "<b64key>" encrypt "<128bithexblock>"                                                                                   
 poetry run transcrypto aes ecb -k "<b64key>" decrypt "<128bithexblock>"                                                                                   
                                                                                                                                                           
 # --- RSA ---                                                                                                                                             
 poetry run transcrypto -p rsa-key rsa new --bits 2048                                                                                                     
 poetry run transcrypto -p rsa-key.pub rsa rawencrypt <plaintext>                                                                                          
 poetry run transcrypto -p rsa-key.priv rsa rawdecrypt <ciphertext>                                                                                        
 poetry run transcrypto -p rsa-key.priv rsa rawsign <message>                                                                                              
 poetry run transcrypto -p rsa-key.pub rsa rawverify <message> <signature>                                                                                 
 poetry run transcrypto -i bin -o b64 -p rsa-key.pub rsa encrypt -a <aad> <plaintext>                                                                      
 poetry run transcrypto -i b64 -o bin -p rsa-key.priv rsa decrypt -a <aad> -- <ciphertext>                                                                 
 poetry run transcrypto -i bin -o b64 -p rsa-key.priv rsa sign <message>                                                                                   
 poetry run transcrypto -i b64 -p rsa-key.pub rsa verify -- <message> <signature>                                                                          
                                                                                                                                                           
 # --- ElGamal ---                                                                                                                                         
 poetry run transcrypto -p eg-key elgamal shared --bits 2048                                                                                               
 poetry run transcrypto -p eg-key elgamal new                                                                                                              
 poetry run transcrypto -p eg-key.pub elgamal rawencrypt <plaintext>                                                                                       
 poetry run transcrypto -p eg-key.priv elgamal rawdecrypt <c1:c2>                                                                                          
 poetry run transcrypto -p eg-key.priv elgamal rawsign <message>                                                                                           
 poetry run transcrypto -p eg-key.pub elgamal rawverify <message> <s1:s2>                                                                                  
 poetry run transcrypto -i bin -o b64 -p eg-key.pub elgamal encrypt <plaintext>                                                                            
 poetry run transcrypto -i b64 -o bin -p eg-key.priv elgamal decrypt -- <ciphertext>                                                                       
 poetry run transcrypto -i bin -o b64 -p eg-key.priv elgamal sign <message>                                                                                
 poetry run transcrypto -i b64 -p eg-key.pub elgamal verify -- <message> <signature>                                                                       
                                                                                                                                                           
 # --- DSA ---                                                                                                                                             
 poetry run transcrypto -p dsa-key dsa shared --p-bits 2048 --q-bits 256                                                                                   
 poetry run transcrypto -p dsa-key dsa new                                                                                                                 
 poetry run transcrypto -p dsa-key.priv dsa rawsign <message>                                                                                              
 poetry run transcrypto -p dsa-key.pub dsa rawverify <message> <s1:s2>                                                                                     
 poetry run transcrypto -i bin -o b64 -p dsa-key.priv dsa sign <message>                                                                                   
 poetry run transcrypto -i b64 -p dsa-key.pub dsa verify -- <message> <signature>                                                                          
                                                                                                                                                           
 # --- Public Bid ---                                                                                                                                      
 poetry run transcrypto -i bin bid new "tomorrow it will rain"                                                                                             
 poetry run transcrypto -o bin bid verify                                                                                                                  
                                                                                                                                                           
 # --- Shamir Secret Sharing (SSS) ---                                                                                                                     
 poetry run transcrypto -p sss-key sss new 3 --bits 1024                                                                                                   
 poetry run transcrypto -p sss-key sss rawshares <secret> <n>                                                                                              
 poetry run transcrypto -p sss-key sss rawrecover                                                                                                          
 poetry run transcrypto -p sss-key sss rawverify <secret>                                                                                                  
 poetry run transcrypto -i bin -p sss-key sss shares <secret> <n>                                                                                          
 poetry run transcrypto -o bin -p sss-key sss recover                                                                                                      
                                                                                                                                                           
 # --- Markdown ---                                                                                                                                        
 poetry run transcrypto markdown > transcrypto.md
```

## `transcrypto aes` Command

```text
Usage: transcrypto aes [OPTIONS] COMMAND [ARGS]...                                                                                                        
                                                                                                                                                           
 AES-256 operations (GCM/ECB) and key derivation. No measures are taken here to prevent timing attacks.                                                    
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ key       Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive salt and iterations. Very good/safe for simple password-to-key but not  │
│           for passwords databases (because of constant salt).                                                                                           │
│ encrypt   AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use               │
│           `--bin`/`--hex`/`--b64` flags. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide the same AAD when      │
│           decrypting and it is NOT included in the `ciphertext`/CT returned by this method!                                                             │
│ decrypt   AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use              │
│           `--bin`/`--hex`/`--b64` flags. Attention: if you provided `-a`/`--aad` (associated data, AAD) during encryption, you will need to provide the │
│           same AAD now!                                                                                                                                 │
│ ecb       AES ECB mode subcommands.                                                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto aes decrypt` Sub-Command

```text
Usage: transcrypto aes decrypt [OPTIONS] CIPHERTEXT                                                                                                       
                                                                                                                                                           
 AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use `--bin`/`--hex`/`--b64`  
 flags. Attention: if you provided `-a`/`--aad` (associated data, AAD) during encryption, you will need to provide the same AAD now!                       
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Input data to decrypt (CT)                                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key   -k      TEXT  Key if `-p`/`--key-path` wasn't used (32 bytes)                                                                                   │
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during encryption)                                                  │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= --                                                   
 F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==                                                                                                  
 AAAAAAB4eXo=                                                                                                                                              
 $ poetry run transcrypto --b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 --                                           
 xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==                                                                                                  
 AAAAAAB4eXo=
```

### `transcrypto aes ecb` Sub-Command

```text
Usage: transcrypto aes ecb [OPTIONS] COMMAND [ARGS]...                                                                                                    
                                                                                                                                                           
 AES ECB mode subcommands.                                                                                                                                 
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key   -k      TEXT  Key if `-p`/`--key-path` wasn't used (32 bytes; raw, or you can use `--bin`/`--hex`/`--b64` flags)                                │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ encrypt   AES-256-ECB: encrypt 16-bytes hex `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting │
│           hash blocks.                                                                                                                                  │
│ decrypt   AES-256-ECB: decrypt 16-bytes hex `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. UNSAFE, except for specifically           │
│           encrypting hash blocks.                                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

#### `transcrypto aes ecb decrypt` Sub-Command

```text
Usage: transcrypto aes ecb decrypt [OPTIONS] CIPHERTEXT                                                                                                   
                                                                                                                                                           
 AES-256-ECB: decrypt 16-bytes hex `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash       
 blocks.                                                                                                                                                   
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Ciphertext block as 32 hex chars (16-bytes)                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 aes ecb -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= decrypt 54ec742ca3da7b752e527b74e3a798d7                           
 00112233445566778899aabbccddeeff
```

#### `transcrypto aes ecb encrypt` Sub-Command

```text
Usage: transcrypto aes ecb encrypt [OPTIONS] PLAINTEXT                                                                                                    
                                                                                                                                                           
 AES-256-ECB: encrypt 16-bytes hex `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash        
 blocks.                                                                                                                                                   
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    plaintext      TEXT  Plaintext block as 32 hex chars (16-bytes)                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 aes ecb -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= encrypt 00112233445566778899aabbccddeeff                           
 54ec742ca3da7b752e527b74e3a798d7
```

### `transcrypto aes encrypt` Sub-Command

```text
Usage: transcrypto aes encrypt [OPTIONS] PLAINTEXT                                                                                                        
                                                                                                                                                           
 AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use `--bin`/`--hex`/`--b64`   
 flags. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide the same AAD when decrypting and it is NOT included in the 
 `ciphertext`/CT returned by this method!                                                                                                                  
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    plaintext      TEXT  Input data to encrypt (PT)                                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key   -k      TEXT  Key if `-p`/`--key-path` wasn't used (32 bytes)                                                                                   │
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- AAAAAAB4eXo=                                      
 F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==                                                                                                  
 $ poetry run transcrypto --b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- AAAAAAB4eXo=                              
 xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==
```

### `transcrypto aes key` Sub-Command

```text
Usage: transcrypto aes key [OPTIONS] PASSWORD                                                                                                             
                                                                                                                                                           
 Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive salt and iterations. Very good/safe for simple password-to-key but not for          
 passwords databases (because of constant salt).                                                                                                           
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    password      TEXT  Password (leading/trailing spaces ignored)                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --out-b64 aes key "correct horse battery staple"                                                                                 
 DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es=                                                                                                              
 $ poetry run transcrypto -p keyfile.out --protect hunter aes key "correct horse battery staple"                                                           
 AES key saved to 'keyfile.out'
```

## `transcrypto bid` Command

```text
Usage: transcrypto bid [OPTIONS] COMMAND [ARGS]...                                                                                                        
                                                                                                                                                           
 Bidding on a `secret` so that you can cryptographically convince a neutral party that the `secret` that was committed to previously was not changed. All  
 methods require file key(s) as `-p`/`--key-path` (see provided examples).                                                                                 
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ new      Generate the bid files for `secret`. Requires `-p`/`--key-path` to set the basename for output files.                                          │
│ verify   Verify the bid files for correctness and reveal the `secret`. Requires `-p`/`--key-path` to set the basename for output files.                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto bid new` Sub-Command

```text
Usage: transcrypto bid new [OPTIONS] SECRET                                                                                                               
                                                                                                                                                           
 Generate the bid files for `secret`. Requires `-p`/`--key-path` to set the basename for output files.                                                     
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    secret      TEXT  Input data to bid to, the protected "secret"                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin -p my-bid bid new "tomorrow it will rain"                                                                                  
 Bid private/public commitments saved to 'my-bid.priv/.pub'
```

### `transcrypto bid verify` Sub-Command

```text
Usage: transcrypto bid verify [OPTIONS]                                                                                                                   
                                                                                                                                                           
 Verify the bid files for correctness and reveal the `secret`. Requires `-p`/`--key-path` to set the basename for output files.                            
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --out-bin -p my-bid bid verify                                                                                                   
 Bid commitment: OK                                                                                                                                        
 Bid secret:                                                                                                                                               
 tomorrow it will rain
```

## `transcrypto dsa` Command

```text
Usage: transcrypto dsa [OPTIONS] COMMAND [ARGS]...                                                                                                        
                                                                                                                                                           
 DSA (Digital Signature Algorithm) asymmetric signing/verifying. No measures are taken here to prevent timing attacks. All methods require file key(s) as  
 `-p`/`--key-path` (see provided examples).                                                                                                                
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ shared      Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is the first step in key generation. `q-bits` should be larger  │
│             than the secrets that will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). The shared key can safely be used │
│             by any number of users to generate their private/public key pairs (with the `new` command). The shared keys are "public". Requires          │
│             `-p`/`--key-path` to set the basename for output files.                                                                                     │
│ new         Generate an individual DSA private/public key pair from a shared key.                                                                       │
│ rawsign     Raw sign *integer* message with private key (BEWARE: no ECDSA/EdDSA padding or validation). Output will 2 *integers* in a `s1:s2` format.   │
│ rawverify   Raw verify *integer* `signature` for *integer* `message` with public key (BEWARE: no ECDSA/EdDSA padding or validation).                    │
│ sign        Sign message with private key.                                                                                                              │
│ verify      Verify `signature` for `message` with public key.                                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto dsa new` Sub-Command

```text
Usage: transcrypto dsa new [OPTIONS]                                                                                                                      
                                                                                                                                                           
 Generate an individual DSA private/public key pair from a shared key.                                                                                     
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p dsa-key dsa new                                                                                                               
 DSA private/public keys saved to 'dsa-key.priv/.pub'
```

### `transcrypto dsa rawsign` Sub-Command

```text
Usage: transcrypto dsa rawsign [OPTIONS] MESSAGE                                                                                                          
                                                                                                                                                           
 Raw sign *integer* message with private key (BEWARE: no ECDSA/EdDSA padding or validation). Output will 2 *integers* in a `s1:s2` format.                 
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Integer message to sign, 1≤`message`<`q`                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p dsa-key.priv dsa rawsign 999                                                                                                  
 2395961484:3435572290
```

### `transcrypto dsa rawverify` Sub-Command

```text
Usage: transcrypto dsa rawverify [OPTIONS] MESSAGE SIGNATURE                                                                                              
                                                                                                                                                           
 Raw verify *integer* `signature` for *integer* `message` with public key (BEWARE: no ECDSA/EdDSA padding or validation).                                  
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message        TEXT  Integer message that was signed earlier, 1≤`message`<`q`                                                            │
│ *    signature      TEXT  Integer putative signature for `message`; expects `s1:s2` format with 2 integers, `s1`,`s2`<`q`                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p dsa-key.pub dsa rawverify 999 2395961484:3435572290                                                                           
 DSA signature: OK                                                                                                                                         
 $ poetry run transcrypto -p dsa-key.pub dsa rawverify 999 2395961484:3435572291                                                                           
 DSA signature: INVALID
```

### `transcrypto dsa shared` Sub-Command

```text
Usage: transcrypto dsa shared [OPTIONS]                                                                                                                   
                                                                                                                                                           
 Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is the first step in key generation. `q-bits` should be larger than the       
 secrets that will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). The shared key can safely be used by any number of users 
 to generate their private/public key pairs (with the `new` command). The shared keys are "public". Requires `-p`/`--key-path` to set the basename for     
 output files.                                                                                                                                             
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --p-bits        INTEGER RANGE   Prime modulus (`p`) size in bits; the default is a safe size                                      │
│ --q-bits        INTEGER RANGE    Prime modulus (`q`) size in bits; the default is a safe size ***IFF*** you are protecting symmetric keys or      │
│                                        regular hashes                                                                                                   │
│                                                                                                                                           │
│ --help                                 Show this message and exit.                                                                                      │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p dsa-key dsa shared --p-bits 128 --q-bits 32  # NEVER use such a small key: example only!                                      
 DSA shared key saved to 'dsa-key.shared'
```

### `transcrypto dsa sign` Sub-Command

```text
Usage: transcrypto dsa sign [OPTIONS] MESSAGE                                                                                                             
                                                                                                                                                           
 Sign message with private key.                                                                                                                            
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Message to sign                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin --out-b64 -p dsa-key.priv dsa sign "xyz"                                                                                   
 yq8InJVpViXh9…BD4par2XuA=
```

### `transcrypto dsa verify` Sub-Command

```text
Usage: transcrypto dsa verify [OPTIONS] MESSAGE SIGNATURE                                                                                                 
                                                                                                                                                           
 Verify `signature` for `message` with public key.                                                                                                         
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message        TEXT  Message that was signed earlier                                                                                     │
│ *    signature      TEXT  Putative signature for `message`                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during signing)                                                     │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 -p dsa-key.pub dsa verify -- eHl6 yq8InJVpViXh9…BD4par2XuA=                                                                
 DSA signature: OK                                                                                                                                         
 $ poetry run transcrypto --b64 -p dsa-key.pub dsa verify -- eLl6 yq8InJVpViXh9…BD4par2XuA=                                                                
 DSA signature: INVALID
```

## `transcrypto elgamal` Command

```text
Usage: transcrypto elgamal [OPTIONS] COMMAND [ARGS]...                                                                                                    
                                                                                                                                                           
 El-Gamal asymmetric cryptography. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see         
 provided examples).                                                                                                                                       
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ shared       Generate a shared El-Gamal key with `bits` prime modulus size, which is the first step in key generation. The shared key can safely be     │
│              used by any number of users to generate their private/public key pairs (with the `new` command). The shared keys are "public". Requires    │
│              `-p`/`--key-path` to set the basename for output files.                                                                                    │
│ new          Generate an individual El-Gamal private/public key pair from a shared key.                                                                 │
│ rawencrypt   Raw encrypt *integer* `message` with public key (BEWARE: no ECIES-style KEM/DEM padding or validation).                                    │
│ rawdecrypt   Raw decrypt *integer* `ciphertext` with private key (BEWARE: no ECIES-style KEM/DEM padding or validation).                                │
│ rawsign      Raw sign *integer* message with private key (BEWARE: no ECIES-style KEM/DEM padding or validation). Output will 2 *integers* in a `s1:s2`  │
│              format.                                                                                                                                    │
│ rawverify    Raw verify *integer* `signature` for *integer* `message` with public key (BEWARE: no ECIES-style KEM/DEM padding or validation).           │
│ encrypt      Encrypt `message` with public key.                                                                                                         │
│ decrypt      Decrypt `ciphertext` with private key.                                                                                                     │
│ sign         Sign message with private key.                                                                                                             │
│ verify       Verify `signature` for `message` with public key.                                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto elgamal decrypt` Sub-Command

```text
Usage: transcrypto elgamal decrypt [OPTIONS] CIPHERTEXT                                                                                                   
                                                                                                                                                           
 Decrypt `ciphertext` with private key.                                                                                                                    
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Ciphertext to decrypt                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during encryption)                                                  │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 --out-bin -p eg-key.priv elgamal decrypt -a eHl6 -- CdFvoQ_IIPFPZLua…kqjhcUTspISxURg==                                     
 abcde
```

### `transcrypto elgamal encrypt` Sub-Command

```text
Usage: transcrypto elgamal encrypt [OPTIONS] PLAINTEXT                                                                                                    
                                                                                                                                                           
 Encrypt `message` with public key.                                                                                                                        
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    plaintext      TEXT  Message to encrypt                                                                                                  │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin --out-b64 -p eg-key.pub elgamal encrypt "abcde" -a "xyz"                                                                   
 CdFvoQ_IIPFPZLua…kqjhcUTspISxURg==
```

### `transcrypto elgamal new` Sub-Command

```text
Usage: transcrypto elgamal new [OPTIONS]                                                                                                                  
                                                                                                                                                           
 Generate an individual El-Gamal private/public key pair from a shared key.                                                                                
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p eg-key elgamal new                                                                                                            
 El-Gamal private/public keys saved to 'eg-key.priv/.pub'
```

### `transcrypto elgamal rawdecrypt` Sub-Command

```text
Usage: transcrypto elgamal rawdecrypt [OPTIONS] CIPHERTEXT                                                                                                
                                                                                                                                                           
 Raw decrypt *integer* `ciphertext` with private key (BEWARE: no ECIES-style KEM/DEM padding or validation).                                               
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Integer ciphertext to decrypt; expects `c1:c2` format with 2 integers, `c1`,`c2`<*modulus*                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p eg-key.priv elgamal rawdecrypt 2948854810728206041:15945988196340032688                                                       
 999
```

### `transcrypto elgamal rawencrypt` Sub-Command

```text
Usage: transcrypto elgamal rawencrypt [OPTIONS] MESSAGE                                                                                                   
                                                                                                                                                           
 Raw encrypt *integer* `message` with public key (BEWARE: no ECIES-style KEM/DEM padding or validation).                                                   
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Integer message to encrypt, 1≤`message`<*modulus*                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p eg-key.pub elgamal rawencrypt 999                                                                                             
 2948854810728206041:15945988196340032688
```

### `transcrypto elgamal rawsign` Sub-Command

```text
Usage: transcrypto elgamal rawsign [OPTIONS] MESSAGE                                                                                                      
                                                                                                                                                           
 Raw sign *integer* message with private key (BEWARE: no ECIES-style KEM/DEM padding or validation). Output will 2 *integers* in a `s1:s2` format.         
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Integer message to sign, 1≤`message`<*modulus*                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p eg-key.priv elgamal rawsign 999                                                                                               
 4674885853217269088:14532144906178302633
```

### `transcrypto elgamal rawverify` Sub-Command

```text
Usage: transcrypto elgamal rawverify [OPTIONS] MESSAGE SIGNATURE                                                                                          
                                                                                                                                                           
 Raw verify *integer* `signature` for *integer* `message` with public key (BEWARE: no ECIES-style KEM/DEM padding or validation).                          
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message        TEXT  Integer message that was signed earlier, 1≤`message`<*modulus*                                                      │
│ *    signature      TEXT  Integer putative signature for `message`; expects `s1:s2` format with 2 integers, `s1`,`s2`<*modulus*               │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p eg-key.pub elgamal rawverify 999 4674885853217269088:14532144906178302633                                                     
 El-Gamal signature: OK                                                                                                                                    
 $ poetry run transcrypto -p eg-key.pub elgamal rawverify 999 4674885853217269088:14532144906178302632                                                     
 El-Gamal signature: INVALID
```

### `transcrypto elgamal shared` Sub-Command

```text
Usage: transcrypto elgamal shared [OPTIONS]                                                                                                               
                                                                                                                                                           
 Generate a shared El-Gamal key with `bits` prime modulus size, which is the first step in key generation. The shared key can safely be used by any number 
 of users to generate their private/public key pairs (with the `new` command). The shared keys are "public". Requires `-p`/`--key-path` to set the         
 basename for output files.                                                                                                                                
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --bits        INTEGER RANGE   Prime modulus (`p`) size in bits; the default is a safe size                                        │
│ --help                               Show this message and exit.                                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p eg-key elgamal shared --bits 64  # NEVER use such a small key: example only!                                                  
 El-Gamal shared key saved to 'eg-key.shared'
```

### `transcrypto elgamal sign` Sub-Command

```text
Usage: transcrypto elgamal sign [OPTIONS] MESSAGE                                                                                                         
                                                                                                                                                           
 Sign message with private key.                                                                                                                            
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Message to sign                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin --out-b64 -p eg-key.priv elgamal sign "xyz"                                                                                
 Xl4hlYK8SHVGw…0fCKJE1XVzA==
```

### `transcrypto elgamal verify` Sub-Command

```text
Usage: transcrypto elgamal verify [OPTIONS] MESSAGE SIGNATURE                                                                                             
                                                                                                                                                           
 Verify `signature` for `message` with public key.                                                                                                         
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message        TEXT  Message that was signed earlier                                                                                     │
│ *    signature      TEXT  Putative signature for `message`                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during signing)                                                     │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 -p eg-key.pub elgamal verify -- eHl6 Xl4hlYK8SHVGw…0fCKJE1XVzA==                                                           
 El-Gamal signature: OK                                                                                                                                    
 $ poetry run transcrypto --b64 -p eg-key.pub elgamal verify -- eLl6 Xl4hlYK8SHVGw…0fCKJE1XVzA==                                                           
 El-Gamal signature: INVALID
```

## `transcrypto gcd` Command

```text
Usage: transcrypto gcd [OPTIONS] A B                                                                                                                      
                                                                                                                                                           
 Greatest Common Divisor (GCD) of integers `a` and `b`.                                                                                                    
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    a      TEXT  Integer, ≥ 0                                                                                                                │
│ *    b      TEXT  Integer, ≥ 0 (can't be both zero)                                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto gcd 462 1071                                                                                                                     
 21                                                                                                                                                        
 $ poetry run transcrypto gcd 0 5                                                                                                                          
 5                                                                                                                                                         
 $ poetry run transcrypto gcd 127 13                                                                                                                       
 1
```

## `transcrypto hash` Command

```text
Usage: transcrypto hash [OPTIONS] COMMAND [ARGS]...                                                                                                       
                                                                                                                                                           
 Cryptographic Hashing (SHA-256 / SHA-512 / file).                                                                                                         
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ sha256   SHA-256 of input `data`.                                                                                                                       │
│ sha512   SHA-512 of input `data`.                                                                                                                       │
│ file     SHA-256/512 hash of file contents, defaulting to SHA-256.                                                                                      │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto hash file` Sub-Command

```text
Usage: transcrypto hash file [OPTIONS] PATH                                                                                                               
                                                                                                                                                           
 SHA-256/512 hash of file contents, defaulting to SHA-256.                                                                                                 
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    path      FILE  Path to existing file                                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --digest          Digest type, SHA-256 ("sha256") or SHA-512 ("sha512")                                                 │
│ --help                           Show this message and exit.                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto hash file /etc/passwd --digest sha512                                                                                            
 8966f5953e79f55dfe34d3dc5b160ac4a4a3f9cbd1c36695a54e28d77c7874dff8595502f8a420608911b87d336d9e83c890f0e7ec11a76cb10b03e757f78aea
```

### `transcrypto hash sha256` Sub-Command

```text
Usage: transcrypto hash sha256 [OPTIONS] DATA                                                                                                             
                                                                                                                                                           
 SHA-256 of input `data`.                                                                                                                                  
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    data      TEXT  Input data (raw text; or use --hex/--b64/--bin)                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin hash sha256 xyz                                                                                                            
 3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282                                                                                          
 $ poetry run transcrypto --b64 hash sha256 -- eHl6  # "xyz" in base-64                                                                                    
 3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282
```

### `transcrypto hash sha512` Sub-Command

```text
Usage: transcrypto hash sha512 [OPTIONS] DATA                                                                                                             
                                                                                                                                                           
 SHA-512 of input `data`.                                                                                                                                  
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    data      TEXT  Input data (raw text; or use --hex/--b64/--bin)                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin hash sha512 xyz                                                                                                            
 4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a58e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728                          
 $ poetry run transcrypto --b64 hash sha512 -- eHl6  # "xyz" in base-64                                                                                    
 4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a58e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728
```

## `transcrypto isprime` Command

```text
Usage: transcrypto isprime [OPTIONS] N                                                                                                                    
                                                                                                                                                           
 Primality test with safe defaults, useful for any integer size.                                                                                           
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    n      TEXT  Integer to test, ≥ 1                                                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto isprime 2305843009213693951                                                                                                      
 True                                                                                                                                                      
 $ poetry run transcrypto isprime 2305843009213693953                                                                                                      
 False
```

## `transcrypto markdown` Command

```text
Usage: transcrypto markdown [OPTIONS]                                                                                                                     
                                                                                                                                                           
 Emit Markdown docs for the CLI (see README.md section "Creating a New Version").                                                                          
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto markdown > transcrypto.md                                                                                                        
 <<saves CLI doc>>
```

## `transcrypto mersenne` Command

```text
Usage: transcrypto mersenne [OPTIONS]                                                                                                                     
                                                                                                                                                           
 Generate (stream) Mersenne prime exponents `k`, also outputting `2^k-1` (the Mersenne prime, `M`) and `M×2^(k-1)` (the associated perfect number),        
 starting at `min-k` and stopping once `k` > `cutoff-k`.                                                                                                   
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --min-k     -k      INTEGER RANGE   Starting exponent `k`, ≥ 1                                                                        │
│ --cutoff-k  -C      INTEGER RANGE   Stop once `k` > `cutoff-k`                                                                    │
│ --help                                    Show this message and exit.                                                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto mersenne -k 0 -C 15                                                                                                              
 k=2  M=3  perfect=6                                                                                                                                       
 k=3  M=7  perfect=28                                                                                                                                      
 k=5  M=31  perfect=496                                                                                                                                    
 k=7  M=127  perfect=8128                                                                                                                                  
 k=13  M=8191  perfect=33550336                                                                                                                            
 k=17  M=131071  perfect=8589869056
```

## `transcrypto mod` Command

```text
Usage: transcrypto mod [OPTIONS] COMMAND [ARGS]...                                                                                                        
                                                                                                                                                           
 Modular arithmetic helpers.                                                                                                                               
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ inv        Modular inverse: find integer 0≤`i`<`m` such that `a×i ≡ 1 (mod m)`. Will only work if `gcd(a,m)==1`, else will fail with a message.         │
│ div        Modular division: find integer 0≤`z`<`m` such that `z×y ≡ x (mod m)`. Will only work if `gcd(y,m)==1` and `y!=0`, else will fail with a      │
│            message.                                                                                                                                     │
│ exp        Modular exponentiation: `a^e mod m`. Efficient, can handle huge values.                                                                      │
│ poly       Efficiently evaluate polynomial with `coeff` coefficients at point `x` modulo `m` (`c₀+c₁×x+c₂×x²+…+cₙ×xⁿ mod m`).                           │
│ lagrange   Lagrange interpolation over modulus `m`: find the `f(x)` solution for the given `x` and `zₙ:f(zₙ)` points `pt`. The modulus `m` must be a    │
│            prime.                                                                                                                                       │
│ crt        Solves Chinese Remainder Theorem (CRT) Pair: finds the unique integer 0≤`x`<`(m1×m2)` satisfying both `x ≡ a1 (mod m1)` and `x ≡ a2 (mod     │
│            m2)`, if `gcd(m1,m2)==1`.                                                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto mod crt` Sub-Command

```text
Usage: transcrypto mod crt [OPTIONS] A1 M1 A2 M2                                                                                                          
                                                                                                                                                           
 Solves Chinese Remainder Theorem (CRT) Pair: finds the unique integer 0≤`x`<`(m1×m2)` satisfying both `x ≡ a1 (mod m1)` and `x ≡ a2 (mod m2)`, if         
 `gcd(m1,m2)==1`.                                                                                                                                          
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    a1      TEXT  Integer residue for first congruence                                                                                       │
│ *    m1      TEXT  Modulus `m1`, ≥ 2 and `gcd(m1,m2)==1`                                                                                      │
│ *    a2      TEXT  Integer residue for second congruence                                                                                      │
│ *    m2      TEXT  Modulus `m2`, ≥ 2 and `gcd(m1,m2)==1`                                                                                      │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto mod crt 6 7 127 13                                                                                                               
 62                                                                                                                                                        
 $ poetry run transcrypto mod crt 12 56 17 19                                                                                                              
 796                                                                                                                                                       
 $ poetry run transcrypto mod crt 6 7 462 1071                                                                                                             
 <<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)
```

### `transcrypto mod div` Sub-Command

```text
Usage: transcrypto mod div [OPTIONS] X Y M                                                                                                                
                                                                                                                                                           
 Modular division: find integer 0≤`z`<`m` such that `z×y ≡ x (mod m)`. Will only work if `gcd(y,m)==1` and `y!=0`, else will fail with a message.          
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    x      TEXT  Integer                                                                                                                     │
│ *    y      TEXT  Integer, cannot be zero                                                                                                     │
│ *    m      TEXT  Modulus `m`, ≥ 2                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto mod div 6 127 13                                                                                                                 
 11                                                                                                                                                        
 $ poetry run transcrypto mod div 6 0 13                                                                                                                   
 <<INVALID>> no modular inverse exists (ModularDivideError)
```

### `transcrypto mod exp` Sub-Command

```text
Usage: transcrypto mod exp [OPTIONS] A E M                                                                                                                
                                                                                                                                                           
 Modular exponentiation: `a^e mod m`. Efficient, can handle huge values.                                                                                   
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    a      TEXT  Integer                                                                                                                     │
│ *    e      TEXT  Integer, ≥ 0                                                                                                                │
│ *    m      TEXT  Modulus `m`, ≥ 2                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto mod exp 438 234 127                                                                                                              
 32                                                                                                                                                        
 $ poetry run transcrypto mod exp 438 234 89854                                                                                                            
 60622
```

### `transcrypto mod inv` Sub-Command

```text
Usage: transcrypto mod inv [OPTIONS] A M                                                                                                                  
                                                                                                                                                           
 Modular inverse: find integer 0≤`i`<`m` such that `a×i ≡ 1 (mod m)`. Will only work if `gcd(a,m)==1`, else will fail with a message.                      
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    a      TEXT  Integer to invert                                                                                                           │
│ *    m      TEXT  Modulus `m`, ≥ 2                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto mod inv 127 13                                                                                                                   
 4                                                                                                                                                         
 $ poetry run transcrypto mod inv 17 3120                                                                                                                  
 2753                                                                                                                                                      
 $ poetry run transcrypto mod inv 462 1071                                                                                                                 
 <<INVALID>> no modular inverse exists (ModularDivideError)
```

### `transcrypto mod lagrange` Sub-Command

```text
Usage: transcrypto mod lagrange [OPTIONS] X M PT...                                                                                                       
                                                                                                                                                           
 Lagrange interpolation over modulus `m`: find the `f(x)` solution for the given `x` and `zₙ:f(zₙ)` points `pt`. The modulus `m` must be a prime.          
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    x       TEXT   Evaluation point `x`                                                                                                      │
│ *    m       TEXT   Modulus `m`, ≥ 2                                                                                                          │
│ *    pt      PT...  Points `zₙ:f(zₙ)` as `key:value` pairs (e.g., `2:4 5:3 7:1`)                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1                                                                                                    
 3  # passes through (2,4), (6,3), (7,1)                                                                                                                   
 $ poetry run transcrypto mod lagrange 11 97 1:1 2:4 3:9 4:16 5:25                                                                                         
 24  # passes through (1,1), (2,4), (3,9), (4,16), (5,25)
```

### `transcrypto mod poly` Sub-Command

```text
Usage: transcrypto mod poly [OPTIONS] X M COEFF...                                                                                                        
                                                                                                                                                           
 Efficiently evaluate polynomial with `coeff` coefficients at point `x` modulo `m` (`c₀+c₁×x+c₂×x²+…+cₙ×xⁿ mod m`).                                        
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    x          TEXT      Evaluation point `x`                                                                                                │
│ *    m          TEXT      Modulus `m`, ≥ 2                                                                                                    │
│ *    coeff      COEFF...  Coefficients (constant-term first: `c₀+c₁×x+c₂×x²+…+cₙ×xⁿ`)                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto mod poly 12 17 10 20 30                                                                                                          
 14  # (10+20×12+30×12² ≡ 14 (mod 17))                                                                                                                     
 $ poetry run transcrypto mod poly 10 97 3 0 0 1 1                                                                                                         
 42  # (3+1×10³+1×10⁴ ≡ 42 (mod 97))
```

## `transcrypto primegen` Command

```text
Usage: transcrypto primegen [OPTIONS] START                                                                                                               
                                                                                                                                                           
 Generate (stream) primes ≥ `start` (prints a limited `count` by default).                                                                                 
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    start      TEXT  Starting integer (inclusive), ≥ 0                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --count  -c      INTEGER RANGE   How many to print                                                                                    │
│ --help                                 Show this message and exit.                                                                                      │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto primegen 100 -c 3                                                                                                                
 101                                                                                                                                                       
 103                                                                                                                                                       
 107
```

## `transcrypto random` Command

```text
Usage: transcrypto random [OPTIONS] COMMAND [ARGS]...                                                                                                     
                                                                                                                                                           
 Cryptographically secure randomness, from the OS CSPRNG.                                                                                                  
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ bits    Random integer with exact bit length = `bits` (MSB will be 1).                                                                                  │
│ int     Uniform random integer in `` range, inclusive.                                                                                                  │
│ bytes   Generates `n` cryptographically secure random bytes.                                                                                            │
│ prime   Generate a random prime with exact bit length = `bits` (MSB will be 1).                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto random bits` Sub-Command

```text
Usage: transcrypto random bits [OPTIONS] BITS                                                                                                             
                                                                                                                                                           
 Random integer with exact bit length = `bits` (MSB will be 1).                                                                                            
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    bits      INTEGER RANGE  Number of bits, ≥ 8                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto random bits 16                                                                                                                   
 36650
```

### `transcrypto random bytes` Sub-Command

```text
Usage: transcrypto random bytes [OPTIONS] N                                                                                                               
                                                                                                                                                           
 Generates `n` cryptographically secure random bytes.                                                                                                      
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    n      INTEGER RANGE  Number of bytes, ≥ 1                                                                                               │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto random bytes 32                                                                                                                  
 6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f
```

### `transcrypto random int` Sub-Command

```text
Usage: transcrypto random int [OPTIONS] MIN_ MAX_                                                                                                         
                                                                                                                                                           
 Uniform random integer in `` range, inclusive.                                                                                                            
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    min_      TEXT  Minimum, ≥ 0                                                                                                             │
│ *    max_      TEXT  Maximum, > `min`                                                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto random int 1000 2000                                                                                                             
 1628
```

### `transcrypto random prime` Sub-Command

```text
Usage: transcrypto random prime [OPTIONS] BITS                                                                                                            
                                                                                                                                                           
 Generate a random prime with exact bit length = `bits` (MSB will be 1).                                                                                   
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    bits      INTEGER RANGE  Bit length, ≥ 11                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto random prime 32                                                                                                                  
 2365910551
```

## `transcrypto rsa` Command

```text
Usage: transcrypto rsa [OPTIONS] COMMAND [ARGS]...                                                                                                        
                                                                                                                                                           
 RSA (Rivest-Shamir-Adleman) asymmetric cryptography. No measures are taken here to prevent timing attacks. All methods require file key(s) as             
 `-p`/`--key-path` (see provided examples).                                                                                                                
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ new          Generate RSA private/public key pair with `bits` modulus size (prime sizes will be `bits`/2). Requires `-p`/`--key-path` to set the        │
│              basename for output files.                                                                                                                 │
│ rawencrypt   Raw encrypt *integer* `message` with public key (BEWARE: no OAEP/PSS padding or validation).                                               │
│ rawdecrypt   Raw decrypt *integer* `ciphertext` with private key (BEWARE: no OAEP/PSS padding or validation).                                           │
│ rawsign      Raw sign *integer* `message` with private key (BEWARE: no OAEP/PSS padding or validation).                                                 │
│ rawverify    Raw verify *integer* `signature` for *integer* `message` with public key (BEWARE: no OAEP/PSS padding or validation).                      │
│ encrypt      Encrypt `message` with public key.                                                                                                         │
│ decrypt      Decrypt `ciphertext` with private key.                                                                                                     │
│ sign         Sign `message` with private key.                                                                                                           │
│ verify       Verify `signature` for `message` with public key.                                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto rsa decrypt` Sub-Command

```text
Usage: transcrypto rsa decrypt [OPTIONS] CIPHERTEXT                                                                                                       
                                                                                                                                                           
 Decrypt `ciphertext` with private key.                                                                                                                    
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Ciphertext to decrypt                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during encryption)                                                  │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 --out-bin -p rsa-key.priv rsa decrypt -a eHl6 -- AO6knI6xwq6TGR…Qy22jiFhXi1eQ==                                            
 abcde
```

### `transcrypto rsa encrypt` Sub-Command

```text
Usage: transcrypto rsa encrypt [OPTIONS] PLAINTEXT                                                                                                        
                                                                                                                                                           
 Encrypt `message` with public key.                                                                                                                        
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    plaintext      TEXT  Message to encrypt                                                                                                  │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin --out-b64 -p rsa-key.pub rsa encrypt "abcde" -a "xyz"                                                                      
 AO6knI6xwq6TGR…Qy22jiFhXi1eQ==
```

### `transcrypto rsa new` Sub-Command

```text
Usage: transcrypto rsa new [OPTIONS]                                                                                                                      
                                                                                                                                                           
 Generate RSA private/public key pair with `bits` modulus size (prime sizes will be `bits`/2). Requires `-p`/`--key-path` to set the basename for output   
 files.                                                                                                                                                    
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --bits        INTEGER RANGE   Modulus size in bits; the default is a safe size                                                    │
│ --help                               Show this message and exit.                                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p rsa-key rsa new --bits 64  # NEVER use such a small key: example only!                                                        
 RSA private/public keys saved to 'rsa-key.priv/.pub'
```

### `transcrypto rsa rawdecrypt` Sub-Command

```text
Usage: transcrypto rsa rawdecrypt [OPTIONS] CIPHERTEXT                                                                                                    
                                                                                                                                                           
 Raw decrypt *integer* `ciphertext` with private key (BEWARE: no OAEP/PSS padding or validation).                                                          
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Integer ciphertext to decrypt, 1≤`ciphertext`<*modulus*                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p rsa-key.priv rsa rawdecrypt 6354905961171348600                                                                               
 999
```

### `transcrypto rsa rawencrypt` Sub-Command

```text
Usage: transcrypto rsa rawencrypt [OPTIONS] MESSAGE                                                                                                       
                                                                                                                                                           
 Raw encrypt *integer* `message` with public key (BEWARE: no OAEP/PSS padding or validation).                                                              
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Integer message to encrypt, 1≤`message`<*modulus*                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p rsa-key.pub rsa rawencrypt 999                                                                                                
 6354905961171348600
```

### `transcrypto rsa rawsign` Sub-Command

```text
Usage: transcrypto rsa rawsign [OPTIONS] MESSAGE                                                                                                          
                                                                                                                                                           
 Raw sign *integer* `message` with private key (BEWARE: no OAEP/PSS padding or validation).                                                                
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Integer message to sign, 1≤`message`<*modulus*                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p rsa-key.priv rsa rawsign 999                                                                                                  
 7632909108672871784
```

### `transcrypto rsa rawverify` Sub-Command

```text
Usage: transcrypto rsa rawverify [OPTIONS] MESSAGE SIGNATURE                                                                                              
                                                                                                                                                           
 Raw verify *integer* `signature` for *integer* `message` with public key (BEWARE: no OAEP/PSS padding or validation).                                     
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message        TEXT  Integer message that was signed earlier, 1≤`message`<*modulus*                                                      │
│ *    signature      TEXT  Integer putative signature for `message`, 1≤`signature`<*modulus*                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p rsa-key.pub rsa rawverify 999 7632909108672871784                                                                             
 RSA signature: OK                                                                                                                                         
 $ poetry run transcrypto -p rsa-key.pub rsa rawverify 999 7632909108672871785                                                                             
 RSA signature: INVALID
```

### `transcrypto rsa sign` Sub-Command

```text
Usage: transcrypto rsa sign [OPTIONS] MESSAGE                                                                                                             
                                                                                                                                                           
 Sign `message` with private key.                                                                                                                          
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Message to sign                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin --out-b64 -p rsa-key.priv rsa sign "xyz"                                                                                   
 91TS7gC6LORiL…6RD23Aejsfxlw==
```

### `transcrypto rsa verify` Sub-Command

```text
Usage: transcrypto rsa verify [OPTIONS] MESSAGE SIGNATURE                                                                                                 
                                                                                                                                                           
 Verify `signature` for `message` with public key.                                                                                                         
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message        TEXT  Message that was signed earlier                                                                                     │
│ *    signature      TEXT  Putative signature for `message`                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during signing)                                                     │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --b64 -p rsa-key.pub rsa verify -- eHl6 91TS7gC6LORiL…6RD23Aejsfxlw==                                                            
 RSA signature: OK                                                                                                                                         
 $ poetry run transcrypto --b64 -p rsa-key.pub rsa verify -- eLl6 91TS7gC6LORiL…6RD23Aejsfxlw==                                                            
 RSA signature: INVALID
```

## `transcrypto sss` Command

```text
Usage: transcrypto sss [OPTIONS] COMMAND [ARGS]...                                                                                                        
                                                                                                                                                           
 SSS (Shamir Shared Secret) secret sharing crypto scheme. No measures are taken here to prevent timing attacks. All methods require file key(s) as         
 `-p`/`--key-path` (see provided examples).                                                                                                                
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ new          Generate the private keys with `bits` prime modulus size and so that at least a `minimum` number of shares are needed to recover the       │
│              secret. This key will be used to generate the shares later (with the `shares` command). Requires `-p`/`--key-path` to set the basename for │
│              output files.                                                                                                                              │
│ rawshares    Raw shares: Issue `count` private shares for an *integer* `secret` (BEWARE: no modern message wrapping, padding or validation).            │
│ rawrecover   Raw recover *integer* secret from shares; will use any available shares that were found (BEWARE: no modern message wrapping, padding or    │
│              validation).                                                                                                                               │
│ rawverify    Raw verify shares against a secret (private params; BEWARE: no modern message wrapping, padding or validation).                            │
│ shares       Shares: Issue `count` private shares for a `secret`.                                                                                       │
│ recover      Recover secret from shares; will use any available shares that were found.                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `transcrypto sss new` Sub-Command

```text
Usage: transcrypto sss new [OPTIONS] MINIMUM                                                                                                              
                                                                                                                                                           
 Generate the private keys with `bits` prime modulus size and so that at least a `minimum` number of shares are needed to recover the secret. This key     
 will be used to generate the shares later (with the `shares` command). Requires `-p`/`--key-path` to set the basename for output files.                   
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    minimum      INTEGER RANGE  Minimum number of shares required to recover secret, ≥ 2                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --bits        INTEGER RANGE   Prime modulus (`p`) size in bits; the default is a safe size ***IFF*** you are protecting symmetric keys; the      │
│                                      number of bits should be comfortably larger than the size of the secret you want to protect with this scheme       │
│                                                                                                                                          │
│ --help                               Show this message and exit.                                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p sss-key sss new 3 --bits 64  # NEVER use such a small key: example only!                                                      
 SSS private/public keys saved to 'sss-key.priv/.pub'
```

### `transcrypto sss rawrecover` Sub-Command

```text
Usage: transcrypto sss rawrecover [OPTIONS]                                                                                                               
                                                                                                                                                           
 Raw recover *integer* secret from shares; will use any available shares that were found (BEWARE: no modern message wrapping, padding or validation).      
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p sss-key sss rawrecover                                                                                                        
 Loaded SSS share: 'sss-key.share.3'                                                                                                                       
 Loaded SSS share: 'sss-key.share.5'                                                                                                                       
 Loaded SSS share: 'sss-key.share.1'  # using only 3 shares: number 2/4 are missing                                                                        
 Secret:                                                                                                                                                   
 999
```

### `transcrypto sss rawshares` Sub-Command

```text
Usage: transcrypto sss rawshares [OPTIONS] SECRET COUNT                                                                                                   
                                                                                                                                                           
 Raw shares: Issue `count` private shares for an *integer* `secret` (BEWARE: no modern message wrapping, padding or validation).                           
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    secret      TEXT           Integer secret to be protected, 1≤`secret`<*modulus*                                                          │
│ *    count       INTEGER RANGE  How many shares to produce; must be ≥ `minimum` used in `new` command or else the `secret` would become unrecoverable   │
│                                                                                                                                               │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p sss-key sss rawshares 999 5                                                                                                   
 SSS 5 individual (private) shares saved to 'sss-key.share.1…5'                                                                                            
 $ rm sss-key.share.2 sss-key.share.4  # this is to simulate only having shares 1,3,5
```

### `transcrypto sss rawverify` Sub-Command

```text
Usage: transcrypto sss rawverify [OPTIONS] SECRET                                                                                                         
                                                                                                                                                           
 Raw verify shares against a secret (private params; BEWARE: no modern message wrapping, padding or validation).                                           
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    secret      TEXT  Integer secret used to generate the shares, ≥ 1                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto -p sss-key sss rawverify 999                                                                                                     
 SSS share 'sss-key.share.3' verification: OK                                                                                                              
 SSS share 'sss-key.share.5' verification: OK                                                                                                              
 SSS share 'sss-key.share.1' verification: OK                                                                                                              
 $ poetry run transcrypto -p sss-key sss rawverify 998                                                                                                     
 SSS share 'sss-key.share.3' verification: INVALID                                                                                                         
 SSS share 'sss-key.share.5' verification: INVALID                                                                                                         
 SSS share 'sss-key.share.1' verification: INVALID
```

### `transcrypto sss recover` Sub-Command

```text
Usage: transcrypto sss recover [OPTIONS]                                                                                                                  
                                                                                                                                                           
 Recover secret from shares; will use any available shares that were found.                                                                                
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --out-bin -p sss-key sss recover                                                                                                 
 Loaded SSS share: 'sss-key.share.3'                                                                                                                       
 Loaded SSS share: 'sss-key.share.5'                                                                                                                       
 Loaded SSS share: 'sss-key.share.1'  # using only 3 shares: number 2/4 are missing                                                                        
 Secret:                                                                                                                                                   
 abcde
```

### `transcrypto sss shares` Sub-Command

```text
Usage: transcrypto sss shares [OPTIONS] SECRET COUNT                                                                                                      
                                                                                                                                                           
 Shares: Issue `count` private shares for a `secret`.                                                                                                      
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    secret      TEXT     Secret to be protected                                                                                              │
│ *    count       INTEGER  How many shares to produce; must be ≥ `minimum` used in `new` command or else the `secret` would become unrecoverable         │
│                                                                                                                                               │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto --bin -p sss-key sss shares "abcde" 5                                                                                            
 SSS 5 individual (private) shares saved to 'sss-key.share.1…5'                                                                                            
 $ rm sss-key.share.2 sss-key.share.4  # this is to simulate only having shares 1,3,5
```

## `transcrypto xgcd` Command

```text
Usage: transcrypto xgcd [OPTIONS] A B                                                                                                                     
                                                                                                                                                           
 Extended Greatest Common Divisor (x-GCD) of integers `a` and `b`, will return `(g, x, y)` where `a×x+b×y==g`.                                             
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    a      TEXT  Integer, ≥ 0                                                                                                                │
│ *    b      TEXT  Integer, ≥ 0 (can't be both zero)                                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run transcrypto xgcd 462 1071                                                                                                                    
 (21, 7, -3)                                                                                                                                               
 $ poetry run transcrypto xgcd 0 5                                                                                                                         
 (5, 0, 1)                                                                                                                                                 
 $ poetry run transcrypto xgcd 127 13                                                                                                                      
 (1, 4, -39)
```
