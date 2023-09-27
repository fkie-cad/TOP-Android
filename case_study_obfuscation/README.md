# TOP - based Obfuscation

## Generating `base.vdex`

It seems like only apps built in *released* mode are AOT optimized via *dex2oat*. This generates `base.vdex`, which is required for *TOP*.

`dex2oat` is used to compile `base.apk`. According to *logcat*:
```
09-25 10:37:50.352 12422 12422 I dex2oat64: /apex/com.android.art/bin/dex2oat64 --input-vdex-fd=-1 --output-vdex-fd=9 --classpath-dir=/data/app/~~4YKdPkapmg_qmwxSkb2y4g==/com.top.poctopobfuscation-qwvpPsFsZJhu1ggCshqc0w== --class-loader-context=PCL[]{} --compact-dex-level=none --compiler-filter=speed-profile --compilation-reason=install --max-image-block-size=524288 --resolve-startup-const-strings=true --generate-mini-debug-info
```
