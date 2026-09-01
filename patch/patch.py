import pathlib, shutil, os, time, subprocess, sys

#путь
src = pathlib.Path(r"C:\Program Files (x86)\Yandex\Online\yachat\yachat.exe")
dst = pathlib.Path(r"C:\Users\krksh\Documents\yachat\yachat_run\yachat.exe")
dst.parent.mkdir(parents=True, exist_ok=True)

#убиваем ячат если висит
for p in ["yachat.exe", "online.exe"]:
    try:
        subprocess.run(["taskkill","/f","/im",p], capture_output=True)
    except: pass
time.sleep(1)

#копируем с ретраем если файл занят
for i in range(5):
    try:
        shutil.copy(src, dst)
        print(f"copy {src} -> {dst}")
        break
    except PermissionError as e:
        print(f"занят, жду {i}: {e}")
        time.sleep(1)
else:
    print("не смог скопировать, файл занят")
    sys.exit(1)

d = bytearray(dst.read_bytes())

def patch(old, new):
    c = 0
    idx = 0
    while True:
        idx = d.find(old, idx)
        if idx == -1:
            break
        nb = new + b'\x00' * (len(old) - len(new))
        d[idx:idx+len(old)] = nb
        c+=1
        idx+=len(old)
    return c

#хост
n1 = patch(b'xmpp.yandex.ru', b'127.0.0.1')
n2 = patch(b'xmpp.yandex-team.ru', b'127.0.0.1')
n3 = patch(b'mobile.online.yandex.net', b'127.0.0.1')
n4 = patch(b'passport.yandex.ru', b'127.0.0.1')
print(f"patch host {n1} {n2} {n3} {n4}")

#токен - патчим функцию 0x644840 (rva 0x244840) -> xor eax,eax; ret
import pefile
pe = pefile.PE(str(dst))
def rva_to_off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - s.VirtualAddress)
off = rva_to_off(0x244840)
print(f"off token {hex(off)} before {d[off:off+10].hex()}")
d[off:off+3] = bytes.fromhex('31 c0 c3')
print(f"after {d[off:off+10].hex()}")

for i in range(5):
    try:
        dst.write_bytes(d)
        print("done", dst)
        break
    except PermissionError as e:
        print(f"запись занята {i}: {e}")
        time.sleep(1)
else:
    print("не смог записать")
    sys.exit(1)

#проверка
print("127 count", d.count(b'127.0.0.1'))
