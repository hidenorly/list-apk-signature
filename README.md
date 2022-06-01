# What's this?

This is tool to dump APK/JAR signature.
Remarkable point is that you can specify folder of pem files.
And this tool result will print with the file name as human understandable signature name.

# How to use?

```
 % ruby list-apk-signature.rb --help
Usage: an apkFile or folder storing apks
    -p, --pemFolder=                 Specify .pem file folder (You can specify multiple paths with ,)
    -s, --useSHA128                  Use SHA128 fingerprint instead of SHA256
    -m, --mode=                      Output mode:per-signature or per-file default:per-file
    -v, --verbose                    Enable verbose status output (default:false)
```

## Usage

```
% ruby list-apk-signature.rb -p ~/work/s/build/make/target/product/security .
{ platform : "xxxx.apk" },
{ "aa:bb:cc:dd:ee:ff:..snip.." : "yyy.apk" },
%
```
