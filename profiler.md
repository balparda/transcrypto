<!-- cspell:disable -->
<!-- auto-generated; DO NOT EDIT! see base.GenerateTyperHelpMarkdown() -->

# `profiler` Command-Line Interface

```text
Usage: profiler [OPTIONS] COMMAND [ARGS]...                                                                                                               
                                                                                                                                                           
 Profile TransCrypto library performance.                                                                                                                  
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --version                                                            Show version and exit.                                                             │
│ --verbose             -v                 INTEGER RANGE [0<=x<=3]     Verbosity (nothing=ERROR, -v=WARNING, -vv=INFO, -vvv=DEBUG).           │
│ --color                   --no-color                                 Force enable/disable colored output (respects NO_COLOR env var if not provided).   │
│                                                                      Defaults to having colors.                                                         │
│ --serial                  --no-serial                                Execute operation serially (i.e. do not use threads/multiprocessing).              │
│                                                                                                                                        │
│ --number              -n                 INTEGER RANGE [1<=x<=1000]  Number of experiments (repeats) for every measurement.                │
│ --confidence          -c                 INTEGER RANGE [50<=x<=99]   Confidence level to evaluate measurements at as int percentage points [50,99],     │
│                                                                      inclusive, representing 50% to 99%                                                 │
│                                                                                                                                            │
│ --bits                -b                 TEXT                        Bit lengths to investigate as "int,int,int"; behaves like arguments for range(),   │
│                                                                      i.e., "start,stop,step", eg. "1000,3000,500" will investigate 1000,1500,2000,2500  │
│                                                                                                                                │
│ --install-completion                                                 Install completion for the current shell.                                          │
│ --show-completion                                                    Show completion for the current shell, to copy it or customize the installation.   │
│ --help                                                               Show this message and exit.                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ primes    Measure regular prime generation.                                                                                                             │
│ dsa       Measure DSA prime generation.                                                                                                                 │
│ markdown  Emit Markdown docs for the CLI (see README.md section "Creating a New Version").                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Examples:                                                                                                                                                 
                                                                                                                                                           
 # --- Primes / DSA ---                                                                                                                                    
 poetry run profiler -n 10 primes                                                                                                                          
 poetry run profiler --no-serial -n 20 dsa                                                                                                                 
                                                                                                                                                           
 # --- Markdown ---                                                                                                                                        
 poetry run profiler markdown > profiler.md
```
