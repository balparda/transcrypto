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

## `profiler dsa` Command

```text
Usage: profiler dsa [OPTIONS]                                                                                                                             
                                                                                                                                                           
 Measure DSA prime generation.                                                                                                                             
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run profiler --no-serial -n 2 -b 1000,1500,100 -c 80 dsa                                                                                         
 Starting PARALLEL DSA primes test                                                                                                                         
 1000 → 236.344 ms ± 273.236 ms [*0.00 s … 509.580 ms]80%CI@2                                                                                              
 1100 → 319.308 ms ± 639.775 ms [*0.00 s … 959.083 ms]80%CI@2                                                                                              
 1200 → 523.885 ms ± 879.981 ms [*0.00 s … 1.40 s]80%CI@2                                                                                                  
 1300 → 506.285 ms ± 687.153 ms [*0.00 s … 1.19 s]80%CI@2                                                                                                  
 1400 → 552.840 ms ± 47.012 ms [505.828 ms … 599.852 ms]80%CI@2                                                                                            
 Finished in 4.12 s
```

## `profiler markdown` Command

```text
Usage: profiler markdown [OPTIONS]                                                                                                                        
                                                                                                                                                           
 Emit Markdown docs for the CLI (see README.md section "Creating a New Version").                                                                          
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run profiler markdown > profiler.md                                                                                                              
 <<saves CLI doc>>
```

## `profiler primes` Command

```text
Usage: profiler primes [OPTIONS]                                                                                                                          
                                                                                                                                                           
 Measure regular prime generation.                                                                                                                         
                                                                                                                                                           
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                                                                                                                                           
 Example:                                                                                                                                                  
                                                                                                                                                           
 $ poetry run profiler -n 30 -b 9000,11000,1000 primes                                                                                                     
 Starting SERIAL regular primes test                                                                                                                       
 9000 → 38.88 s ± 14.74 s [24.14 s … 53.63 s]98%CI@30                                                                                                      
 10000 → 41.26 s ± 22.82 s [18.44 s … 1.07 min]98%CI@30                                                                                                    
 Finished in 40.07 min
```
