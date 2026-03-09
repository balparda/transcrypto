<!-- cspell:disable -->
<!-- auto-generated; DO NOT EDIT! see base.GenerateTyperHelpMarkdown() -->

# `safetrans` Command-Line Interface

```text
Usage: safetrans [OPTIONS] COMMAND [ARGS]...                                                                                                              
                                                                                                                                                           
 safetrans: CLI for number theory, hash, AES, RSA, El-Gamal, DSA, bidding, SSS, and more.                                                                  
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --version                                                        Show version and exit.                                                                 │
│ --verbose             -v                INTEGER RANGE [0<=x<=3]  Verbosity (nothing=ERROR, -v=WARNING, -vv=INFO, -vvv=DEBUG).               │
│ --color                   --no-color                             Force enable/disable colored output (respects NO_COLOR env var if not provided).       │
│                                                                  Defaults to having colors.                                                             │
│ --input-format        -i                            How to format inputs: "hex" (default hexadecimal), "b64" (base64), or "bin" (binary);  │
│                                                                  sometimes base64 will start with "-" and that can conflict with other flags, so use "  │
│                                                                  -- " before positional arguments if needed.                                            │
│                                                                                                                                           │
│ --output-format       -o                            How to format outputs: "hex" (default hexadecimal), "b64" (base64), or "bin" (binary). │
│                                                                                                                                           │
│ --key-path            -p                PATH                     File path to serialized key object, if key is needed for operation                     │
│ --protect             -x                TEXT                     Password to encrypt/decrypt key file if using the `-p`/`--key-path` option             │
│ --install-completion                                             Install completion for the current shell.                                              │
│ --show-completion                                                Show completion for the current shell, to copy it or customize the installation.       │
│ --help                                                           Show this message and exit.                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ markdown  Emit Markdown docs for the CLI (see README.md section "Creating a New Version").                                                              │
│ hash      Cryptographic Hashing (SHA-256 / SHA-512 / file).                                                                                             │
│ aes       AES-256 operations (GCM/ECB) and key derivation. No measures are taken here to prevent timing attacks.                                        │
│ bid       Bidding on a `secret` so that you can cryptographically convince a neutral party that the `secret` that was committed to previously was not   │
│           changed. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All non-int inputs are raw, or you can use             │
│           `--input-format <hex|b64|bin>`. No measures are taken here to prevent timing attacks.                                                         │
│ sss       SSS (Shamir Shared Secret) secret sharing crypto scheme. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All    │
│           non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. No measures are taken here to prevent timing attacks.                  │
│ random    Cryptographically secure randomness, from the OS CSPRNG.                                                                                      │
│ rsa       RSA (Rivest-Shamir-Adleman) asymmetric cryptography. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All        │
│           non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you     │
│           will need to provide the same AAD when decrypting/verifying and it is NOT included in the `ciphertext`/CT or `signature` returned by these    │
│           methods! No measures are taken here to prevent timing attacks.                                                                                │
│ dsa       DSA (Digital Signature Algorithm) asymmetric signing/verifying. All methods require file key(s) as `-p`/`--key-path` (see provided examples). │
│           All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you │
│           will need to provide the same AAD when decrypting/verifying and it is NOT included in the `signature` returned by these methods! No measures  │
│           are taken here to prevent timing attacks.                                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 # --- Randomness ---                                                                                                                                      
 poetry run safetrans random bits 16                                                                                                                       
 poetry run safetrans random int 1000 2000                                                                                                                 
 poetry run safetrans random bytes 32                                                                                                                      
 poetry run safetrans random prime 64                                                                                                                      
                                                                                                                                                           
 # --- Hashing ---                                                                                                                                         
 poetry run safetrans hash sha256 xyz                                                                                                                      
 poetry run safetrans --input-format b64 hash sha512 -- eHl6                                                                                               
 poetry run safetrans hash file /etc/passwd --digest sha512                                                                                                
                                                                                                                                                           
 # --- AES ---                                                                                                                                             
 poetry run safetrans --output-format b64 aes key "correct horse battery staple"                                                                           
 poetry run safetrans -i b64 -o b64 aes encrypt -k "<b64key>" -- "secret"                                                                                  
 poetry run safetrans -i b64 -o b64 aes decrypt -k "<b64key>" -- "<ciphertext>"                                                                            
                                                                                                                                                           
 # --- RSA ---                                                                                                                                             
 poetry run safetrans -p rsa-key rsa new --bits 2048                                                                                                       
 poetry run safetrans -i bin -o b64 -p rsa-key.pub rsa encrypt -a <aad> <plaintext>                                                                        
 poetry run safetrans -i b64 -o bin -p rsa-key.priv rsa decrypt -a <aad> -- <ciphertext>                                                                   
 poetry run safetrans -i bin -o b64 -p rsa-key.priv rsa sign <message>                                                                                     
 poetry run safetrans -i b64 -p rsa-key.pub rsa verify -- <message> <signature>                                                                            
                                                                                                                                                           
 # --- DSA ---                                                                                                                                             
 poetry run safetrans -p dsa-key dsa shared --p-bits 2048 --q-bits 256                                                                                     
 poetry run safetrans -p dsa-key dsa new                                                                                                                   
 poetry run safetrans -i bin -o b64 -p dsa-key.priv dsa sign <message>                                                                                     
 poetry run safetrans -i b64 -p dsa-key.pub dsa verify -- <message> <signature>                                                                            
                                                                                                                                                           
 # --- Public Bid ---                                                                                                                                      
 poetry run safetrans -i bin bid new "tomorrow it will rain"                                                                                               
 poetry run safetrans -o bin bid verify                                                                                                                    
                                                                                                                                                           
 # --- Shamir Secret Sharing (SSS) ---                                                                                                                     
 poetry run safetrans -p sss-key sss new 3 --bits 1024                                                                                                     
 poetry run safetrans -i bin -p sss-key sss shares <secret> <n>                                                                                            
 poetry run safetrans -o bin -p sss-key sss recover                                                                                                        
                                                                                                                                                           
 # --- Markdown ---                                                                                                                                        
 poetry run safetrans markdown > safetrans.md
```

## `safetrans aes` Command

```text
Usage: safetrans aes [OPTIONS] COMMAND [ARGS]...                                                                                                          
                                                                                                                                                           
 AES-256 operations (GCM/ECB) and key derivation. No measures are taken here to prevent timing attacks.                                                    
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ key      Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive salt and iterations. Very good/safe for simple password-to-key but not   │
│          for passwords databases (because of constant salt).                                                                                            │
│ encrypt  AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use                │
│          `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide the same AAD when      │
│          decrypting and it is NOT included in the `ciphertext`/CT returned by this method!                                                              │
│ decrypt  AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use               │
│          `--input-format <hex|b64|bin>`. Attention: if you provided `-a`/`--aad` (associated data, AAD) during encryption, you will need to provide the │
│          same AAD now!                                                                                                                                  │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `safetrans aes decrypt` Sub-Command

```text
Usage: safetrans aes decrypt [OPTIONS] CIPHERTEXT                                                                                                         
                                                                                                                                                           
 AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use `--input-format          
 <hex|b64|bin>`. Attention: if you provided `-a`/`--aad` (associated data, AAD) during encryption, you will need to provide the same AAD now!              
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Input data to decrypt (CT)                                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key   -k      TEXT  Key if `-p`/`--key-path` wasn't used (32 bytes)                                                                                   │
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during encryption)                                                  │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i b64 -o b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= --                                                       
 F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==                                                                                                  
 AAAAAAB4eXo=                                                                                                                                              
 $ poetry run safetrans -i b64 -o b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 --                                               
 xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==                                                                                                  
 AAAAAAB4eXo=
```

### `safetrans aes encrypt` Sub-Command

```text
Usage: safetrans aes encrypt [OPTIONS] PLAINTEXT                                                                                                          
                                                                                                                                                           
 AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use `--input-format           
 <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide the same AAD when decrypting and it is NOT        
 included in the `ciphertext`/CT returned by this method!                                                                                                  
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    plaintext      TEXT  Input data to encrypt (PT)                                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --key   -k      TEXT  Key if `-p`/`--key-path` wasn't used (32 bytes)                                                                                   │
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i b64 -o b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- AAAAAAB4eXo=                                          
 F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==                                                                                                  
 $ poetry run safetrans -i b64 -o b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- AAAAAAB4eXo=                                  
 xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==
```

### `safetrans aes key` Sub-Command

```text
Usage: safetrans aes key [OPTIONS] PASSWORD                                                                                                               
                                                                                                                                                           
 Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive salt and iterations. Very good/safe for simple password-to-key but not for          
 passwords databases (because of constant salt).                                                                                                           
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    password      TEXT  Password (leading/trailing spaces ignored)                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -o b64 aes key "correct horse battery staple"                                                                                      
 DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es=                                                                                                              
 $ poetry run safetrans -p keyfile.out --protect hunter aes key "correct horse battery staple"                                                             
 AES key saved to 'keyfile.out'
```

## `safetrans bid` Command

```text
Usage: safetrans bid [OPTIONS] COMMAND [ARGS]...                                                                                                          
                                                                                                                                                           
 Bidding on a `secret` so that you can cryptographically convince a neutral party that the `secret` that was committed to previously was not changed. All  
 methods require file key(s) as `-p`/`--key-path` (see provided examples). All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. No   
 measures are taken here to prevent timing attacks.                                                                                                        
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ new     Generate the bid files for `secret`.                                                                                                            │
│ verify  Verify the bid files for correctness and reveal the `secret`.                                                                                   │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `safetrans bid new` Sub-Command

```text
Usage: safetrans bid new [OPTIONS] SECRET                                                                                                                 
                                                                                                                                                           
 Generate the bid files for `secret`.                                                                                                                      
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    secret      TEXT  Input data to bid to, the protected "secret"                                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i bin -p my-bid bid new "tomorrow it will rain"                                                                                   
 Bid private/public commitments saved to 'my-bid.priv/.pub'
```

### `safetrans bid verify` Sub-Command

```text
Usage: safetrans bid verify [OPTIONS]                                                                                                                     
                                                                                                                                                           
 Verify the bid files for correctness and reveal the `secret`.                                                                                             
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -o bin -p my-bid bid verify                                                                                                        
 Bid commitment: OK                                                                                                                                        
 Bid secret:                                                                                                                                               
 tomorrow it will rain
```

## `safetrans dsa` Command

```text
Usage: safetrans dsa [OPTIONS] COMMAND [ARGS]...                                                                                                          
                                                                                                                                                           
 DSA (Digital Signature Algorithm) asymmetric signing/verifying. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All non-int 
 inputs are raw, or you can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide    
 the same AAD when decrypting/verifying and it is NOT included in the `signature` returned by these methods! No measures are taken here to prevent timing  
 attacks.                                                                                                                                                  
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ shared  Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is the first step in key generation. `q-bits` should be larger than │
│         the secrets that will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). The shared key can safely be used by any   │
│         number of users to generate their private/public key pairs (with the `new` command). The shared keys are "public".                              │
│ new     Generate an individual DSA private/public key pair from a shared key.                                                                           │
│ sign    Sign message with private key.                                                                                                                  │
│ verify  Verify `signature` for `message` with public key.                                                                                               │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `safetrans dsa new` Sub-Command

```text
Usage: safetrans dsa new [OPTIONS]                                                                                                                        
                                                                                                                                                           
 Generate an individual DSA private/public key pair from a shared key.                                                                                     
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -p dsa-key dsa new                                                                                                                 
 DSA private/public keys saved to 'dsa-key.priv/.pub'
```

### `safetrans dsa shared` Sub-Command

```text
Usage: safetrans dsa shared [OPTIONS]                                                                                                                     
                                                                                                                                                           
 Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is the first step in key generation. `q-bits` should be larger than the       
 secrets that will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). The shared key can safely be used by any number of users 
 to generate their private/public key pairs (with the `new` command). The shared keys are "public".                                                        
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --p-bits  -b      INTEGER RANGE   Prime modulus (`p`) size in bits, ≥16; the default (4096) is a safe size                        │
│ --q-bits  -q      INTEGER RANGE    Prime modulus (`q`) size in bits, ≥8; the default (544) is a safe size ***IFF*** you are protecting symmetric  │
│                                          keys or regular hashes                                                                                         │
│                                                                                                                                           │
│ --help                                   Show this message and exit.                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -p dsa-key dsa shared --p-bits 128 --q-bits 32  # NEVER use such a small key: example only!                                        
 DSA shared key saved to 'dsa-key.shared'
```

### `safetrans dsa sign` Sub-Command

```text
Usage: safetrans dsa sign [OPTIONS] MESSAGE                                                                                                               
                                                                                                                                                           
 Sign message with private key.                                                                                                                            
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Message to sign                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i bin -o b64 -p dsa-key.priv dsa sign "xyz"                                                                                       
 yq8InJVpViXh9…BD4par2XuA=
```

### `safetrans dsa verify` Sub-Command

```text
Usage: safetrans dsa verify [OPTIONS] MESSAGE SIGNATURE                                                                                                   
                                                                                                                                                           
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
                                                                                                                                                           
 $ poetry run safetrans -i b64 -p dsa-key.pub dsa verify -- eHl6 yq8InJVpViXh9…BD4par2XuA=                                                                 
 DSA signature: OK                                                                                                                                         
 $ poetry run safetrans -i b64 -p dsa-key.pub dsa verify -- eLl6 yq8InJVpViXh9…BD4par2XuA=                                                                 
 DSA signature: INVALID
```

## `safetrans hash` Command

```text
Usage: safetrans hash [OPTIONS] COMMAND [ARGS]...                                                                                                         
                                                                                                                                                           
 Cryptographic Hashing (SHA-256 / SHA-512 / file).                                                                                                         
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ sha256  SHA-256 of input `data`.                                                                                                                        │
│ sha512  SHA-512 of input `data`.                                                                                                                        │
│ file    SHA-256/512 hash of file contents, defaulting to SHA-256.                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `safetrans hash file` Sub-Command

```text
Usage: safetrans hash file [OPTIONS] PATH                                                                                                                 
                                                                                                                                                           
 SHA-256/512 hash of file contents, defaulting to SHA-256.                                                                                                 
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    path      FILE  Path to existing file                                                                                                    │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --digest  -d        Digest type, SHA-256 ("sha256") or SHA-512 ("sha512")                                               │
│ --help                             Show this message and exit.                                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans hash file /etc/passwd --digest sha512                                                                                              
 8966f5953e79f55dfe34d3dc5b160ac4a4a3f9cbd1c36695a54e28d77c7874dff8595502f8a420608911b87d336d9e83c890f0e7ec11a76cb10b03e757f78aea
```

### `safetrans hash sha256` Sub-Command

```text
Usage: safetrans hash sha256 [OPTIONS] DATA                                                                                                               
                                                                                                                                                           
 SHA-256 of input `data`.                                                                                                                                  
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    data      TEXT  Input data (raw text; or `--input-format <hex|b64|bin>`)                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i bin hash sha256 xyz                                                                                                             
 3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282                                                                                          
 $ poetry run safetrans -i b64 hash sha256 -- eHl6  # "xyz" in base-64                                                                                     
 3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282
```

### `safetrans hash sha512` Sub-Command

```text
Usage: safetrans hash sha512 [OPTIONS] DATA                                                                                                               
                                                                                                                                                           
 SHA-512 of input `data`.                                                                                                                                  
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    data      TEXT  Input data (raw text; or `--input-format <hex|b64|bin>`)                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i bin hash sha512 xyz                                                                                                             
 4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a58e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728                          
 $ poetry run safetrans -i b64 hash sha512 -- eHl6  # "xyz" in base-64                                                                                     
 4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a58e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728
```

## `safetrans markdown` Command

```text
Usage: safetrans markdown [OPTIONS]                                                                                                                       
                                                                                                                                                           
 Emit Markdown docs for the CLI (see README.md section "Creating a New Version").                                                                          
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans markdown > safetrans.md                                                                                                            
 <<saves CLI doc>>
```

## `safetrans random` Command

```text
Usage: safetrans random [OPTIONS] COMMAND [ARGS]...                                                                                                       
                                                                                                                                                           
 Cryptographically secure randomness, from the OS CSPRNG.                                                                                                  
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ bits   Random integer with exact bit length = `bits` (MSB will be 1).                                                                                   │
│ int    Uniform random integer in `` range, inclusive.                                                                                                   │
│ bytes  Generates `n` cryptographically secure random bytes.                                                                                             │
│ prime  Generate a random prime with exact bit length = `bits` (MSB will be 1).                                                                          │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `safetrans random bits` Sub-Command

```text
Usage: safetrans random bits [OPTIONS] BITS                                                                                                               
                                                                                                                                                           
 Random integer with exact bit length = `bits` (MSB will be 1).                                                                                            
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    bits      INTEGER RANGE  Number of bits, ≥ 8                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans random bits 16                                                                                                                     
 36650
```

### `safetrans random bytes` Sub-Command

```text
Usage: safetrans random bytes [OPTIONS] N                                                                                                                 
                                                                                                                                                           
 Generates `n` cryptographically secure random bytes.                                                                                                      
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    n      INTEGER RANGE  Number of bytes, ≥ 1                                                                                               │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans random bytes 32                                                                                                                    
 6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f
```

### `safetrans random int` Sub-Command

```text
Usage: safetrans random int [OPTIONS] MIN_ MAX_                                                                                                           
                                                                                                                                                           
 Uniform random integer in `` range, inclusive.                                                                                                            
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    min_      TEXT  Minimum, ≥ 0                                                                                                             │
│ *    max_      TEXT  Maximum, > `min`                                                                                                         │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans random int 1000 2000                                                                                                               
 1628
```

### `safetrans random prime` Sub-Command

```text
Usage: safetrans random prime [OPTIONS] BITS                                                                                                              
                                                                                                                                                           
 Generate a random prime with exact bit length = `bits` (MSB will be 1).                                                                                   
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    bits      INTEGER RANGE  Bit length, ≥ 11                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans random prime 32                                                                                                                    
 2365910551
```

## `safetrans rsa` Command

```text
Usage: safetrans rsa [OPTIONS] COMMAND [ARGS]...                                                                                                          
                                                                                                                                                           
 RSA (Rivest-Shamir-Adleman) asymmetric cryptography. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All non-int inputs are 
 raw, or you can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide the same AAD  
 when decrypting/verifying and it is NOT included in the `ciphertext`/CT or `signature` returned by these methods! No measures are taken here to prevent   
 timing attacks.                                                                                                                                           
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ new      Generate RSA private/public key pair with `bits` modulus size (prime sizes will be `bits`/2).                                                  │
│ encrypt  Encrypt `message` with public key.                                                                                                             │
│ decrypt  Decrypt `ciphertext` with private key.                                                                                                         │
│ sign     Sign `message` with private key.                                                                                                               │
│ verify   Verify `signature` for `message` with public key.                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `safetrans rsa decrypt` Sub-Command

```text
Usage: safetrans rsa decrypt [OPTIONS] CIPHERTEXT                                                                                                         
                                                                                                                                                           
 Decrypt `ciphertext` with private key.                                                                                                                    
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    ciphertext      TEXT  Ciphertext to decrypt                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be exactly the same as used during encryption)                                                  │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i b64 -o bin -p rsa-key.priv rsa decrypt -a eHl6 -- AO6knI6xwq6TGR…Qy22jiFhXi1eQ==                                                
 abcde
```

### `safetrans rsa encrypt` Sub-Command

```text
Usage: safetrans rsa encrypt [OPTIONS] PLAINTEXT                                                                                                          
                                                                                                                                                           
 Encrypt `message` with public key.                                                                                                                        
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    plaintext      TEXT  Message to encrypt                                                                                                  │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i bin -o b64 -p rsa-key.pub rsa encrypt "abcde" -a "xyz"                                                                          
 AO6knI6xwq6TGR…Qy22jiFhXi1eQ==
```

### `safetrans rsa new` Sub-Command

```text
Usage: safetrans rsa new [OPTIONS]                                                                                                                        
                                                                                                                                                           
 Generate RSA private/public key pair with `bits` modulus size (prime sizes will be `bits`/2).                                                             
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --bits  -b      INTEGER RANGE   Modulus size in bits, ≥16; the default (3332) is a safe size                                      │
│ --help                                 Show this message and exit.                                                                                      │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -p rsa-key rsa new --bits 64  # NEVER use such a small key: example only!                                                          
 RSA private/public keys saved to 'rsa-key.priv/.pub'
```

### `safetrans rsa sign` Sub-Command

```text
Usage: safetrans rsa sign [OPTIONS] MESSAGE                                                                                                               
                                                                                                                                                           
 Sign `message` with private key.                                                                                                                          
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    message      TEXT  Message to sign                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --aad   -a      TEXT  Associated data (optional; has to be separately sent to receiver/stored)                                                          │
│ --help                Show this message and exit.                                                                                                       │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -i bin -o b64 -p rsa-key.priv rsa sign "xyz"                                                                                       
 91TS7gC6LORiL…6RD23Aejsfxlw==
```

### `safetrans rsa verify` Sub-Command

```text
Usage: safetrans rsa verify [OPTIONS] MESSAGE SIGNATURE                                                                                                   
                                                                                                                                                           
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
                                                                                                                                                           
 $ poetry run safetrans -i b64 -p rsa-key.pub rsa verify -- eHl6 91TS7gC6LORiL…6RD23Aejsfxlw==                                                             
 RSA signature: OK                                                                                                                                         
 $ poetry run safetrans -i b64 -p rsa-key.pub rsa verify -- eLl6 91TS7gC6LORiL…6RD23Aejsfxlw==                                                             
 RSA signature: INVALID
```

## `safetrans sss` Command

```text
Usage: safetrans sss [OPTIONS] COMMAND [ARGS]...                                                                                                          
                                                                                                                                                           
 SSS (Shamir Shared Secret) secret sharing crypto scheme. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All non-int inputs 
 are raw, or you can use `--input-format <hex|b64|bin>`. No measures are taken here to prevent timing attacks.                                             
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ new      Generate the private keys with `bits` prime modulus size and so that at least a `minimum` number of shares are needed to recover the secret.   │
│          This key will be used to generate the shares later (with the `shares` command).                                                                │
│ shares   Shares: Issue `count` private shares for a `secret`.                                                                                           │
│ recover  Recover secret from shares; will use any available shares that were found.                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

### `safetrans sss new` Sub-Command

```text
Usage: safetrans sss new [OPTIONS] MINIMUM                                                                                                                
                                                                                                                                                           
 Generate the private keys with `bits` prime modulus size and so that at least a `minimum` number of shares are needed to recover the secret. This key     
 will be used to generate the shares later (with the `shares` command).                                                                                    
                                                                                                                                                           
╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    minimum      INTEGER RANGE  Minimum number of shares required to recover secret, ≥ 2                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --bits  -b      INTEGER RANGE   Prime modulus (`p`) size in bits, ≥16; the default (1024) is a safe size ***IFF*** you are protecting symmetric  │
│                                        keys; the number of bits should be comfortably larger than the size of the secret you want to protect with this  │
│                                        scheme                                                                                                           │
│                                                                                                                                          │
│ --help                                 Show this message and exit.                                                                                      │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -p sss-key sss new 3 --bits 64  # NEVER use such a small key: example only!                                                        
 SSS private/public keys saved to 'sss-key.priv/.pub'
```

### `safetrans sss recover` Sub-Command

```text
Usage: safetrans sss recover [OPTIONS]                                                                                                                    
                                                                                                                                                           
 Recover secret from shares; will use any available shares that were found.                                                                                
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run safetrans -o bin -p sss-key sss recover                                                                                                      
 Loaded SSS share: 'sss-key.share.3'                                                                                                                       
 Loaded SSS share: 'sss-key.share.5'                                                                                                                       
 Loaded SSS share: 'sss-key.share.1'  # using only 3 shares: number 2/4 are missing                                                                        
 Secret:                                                                                                                                                   
 abcde
```

### `safetrans sss shares` Sub-Command

```text
Usage: safetrans sss shares [OPTIONS] SECRET COUNT                                                                                                        
                                                                                                                                                           
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
                                                                                                                                                           
 $ poetry run safetrans -i bin -p sss-key sss shares "abcde" 5                                                                                             
 SSS 5 individual (private) shares saved to 'sss-key.share.1…5'                                                                                            
 $ rm sss-key.share.2 sss-key.share.4  # this is to simulate only having shares 1,3,5
```
