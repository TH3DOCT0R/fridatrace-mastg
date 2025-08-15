# HOWTO
1) adb root && adb shell setenforce 0  (if test device/emulator allows)
2) Start frida-server on device: `./frida-server &`
3) On host: `pip install frida-tools`
4) Find target app pid: `frida-ps -Uai`
5) Run hook:
   ```bash
   frida -U -f com.example.app -l frida/sslpinning_bypass.js --no-pause
   ```
6. Observe logs; capture evidence to `evidence/`.
