## Source files for Empire integration

### Files

#### data/module_source/python/management/socks-src.py
This contains the AROX source code. The following modifications are made to `arox.py`:
- `main()` is replaced with a templatized argument for the server host and call to `relay_main()`
- `SocksServer` class is removed
- Extraneous comments are removed

#### lib/modules/python/management/multu/socks.py
This contains the module code for the SOCKS agent