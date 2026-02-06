<!-- cspell:disable -->
<!-- auto-generated; DO NOT EDIT! see base.GenerateTyperHelpMarkdown() -->

# `transcrypto` Command-Line Interface

```text
Usage: transcrypto [OPTIONS] COMMAND [ARGS]...                                                                                                            
                                                                                                                                                           
 transcrypto: CLI for number theory, hash, AES, RSA, El-Gamal, DSA, bidding, SSS, and more.                                                                
                                                                                                                                                           
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
│ isprime   Primality test with safe defaults, useful for any integer size.                                                                               │
│ primegen  Generate (stream) primes ≥ `start` (prints a limited `count` by default).                                                                     │
│ mersenne  Generate (stream) Mersenne prime exponents `k`, also outputting `2^k-1` (the Mersenne prime, `M`) and `M×2^(k-1)` (the associated perfect     │
│           number), starting at `min-k` and stopping once `k` > `max-k`.                                                                                 │
│ gcd       Greatest Common Divisor (GCD) of integers `a` and `b`.                                                                                        │
│ xgcd      Extended Greatest Common Divisor (x-GCD) of integers `a` and `b`, will return `(g, x, y)` where `a×x+b×y==g`.                                 │
│ hash      Cryptographic Hashing (SHA-256 / SHA-512 / file).                                                                                             │
│ aes       AES-256 operations (GCM/ECB) and key derivation. No measures are taken here to prevent timing attacks.                                        │
│ bid       Bidding on a `secret` so that you can cryptographically convince a neutral party that the `secret` that was committed to previously was not   │
│           changed. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All non-int inputs are raw, or you can use             │
│           `--input-format <hex|b64|bin>`. No measures are taken here to prevent timing attacks.                                                         │
│ sss       SSS (Shamir Shared Secret) secret sharing crypto scheme. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All    │
│           non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. No measures are taken here to prevent timing attacks.                  │
│ random    Cryptographically secure randomness, from the OS CSPRNG.                                                                                      │
│ mod       Modular arithmetic helpers.                                                                                                                   │
│ rsa       RSA (Rivest-Shamir-Adleman) asymmetric cryptography. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All        │
│           non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you     │
│           will need to provide the same AAD when decrypting/verifying and it is NOT included in the `ciphertext`/CT or `signature` returned by these    │
│           methods! No measures are taken here to prevent timing attacks.                                                                                │
│ elgamal   El-Gamal asymmetric cryptography. All methods require file key(s) as `-p`/`--key-path` (see provided examples). All non-int inputs are raw,   │
│           or you can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide the    │
│           same AAD when decrypting/verifying and it is NOT included in the `ciphertext`/CT or `signature` returned by these methods! No measures are    │
│           taken here to prevent timing attacks.                                                                                                         │
│ dsa       DSA (Digital Signature Algorithm) asymmetric signing/verifying. All methods require file key(s) as `-p`/`--key-path` (see provided examples). │
│           All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` (associated data, AAD), you │
│           will need to provide the same AAD when decrypting/verifying and it is NOT included in the `signature` returned by these methods! No measures  │
│           are taken here to prevent timing attacks.                                                                                                     │
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
 poetry run transcrypto aes ecb encrypt -k "<b64key>" "<128bithexblock>"                                                                                   
 poetry run transcrypto aes ecb decrypt -k "<b64key>" "<128bithexblock>"                                                                                   
                                                                                                                                                           
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
