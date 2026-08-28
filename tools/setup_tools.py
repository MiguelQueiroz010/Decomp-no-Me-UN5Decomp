from pathlib import Path
import hashlib
import io
import platform
import sys
import tarfile
import urllib.error
import urllib.request


WIBO_VERSION = "1.2.0"
WIBO_ASSETS = {
    ("Linux", "x86_64"): (
        "wibo-x86_64",
        "13f86a2d618f0dbe67179d349625345eabf9b46450295cb4c904e49f6aff85af",
    ),
}

MWCCPS2_VERSION = "2.4-001213"
MWCCPS2_URL = (
    "https://github.com/decompme/compilers/releases/download/compilers/"
    "mwcps2-2.4-001213.tar.gz"
)
MWCCPS2_FILES = (
    "asm_r5900_elf.exe",
    "LMGR326B.DLL",
    "mwccps2.exe",
    "mwldps2.exe",
)

OBJDIFF_VERSION = "3.8.0"
OBJDIFF_ASSETS = {
    ("Linux", "x86_64"): (
        "objdiff-cli-linux-x86_64",
        "bc1e047126f9c6914bd1695798175234642ab9eaf45e886f841b59a4231e1a81",
    ),
    ("Linux", "aarch64"): (
        "objdiff-cli-linux-aarch64",
        "4f19a2f2ce2fec515db65c90cc6d7d4dfb33fd7bc514f3985632b0c7d1b586c9",
    ),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def install_compiler(root: Path) -> bool:
    destination = root / "tools/mwccps2"
    required = [destination / name for name in MWCCPS2_FILES]

    if all(path.is_file() for path in required):
        print(f"[ok] Metrowerks {MWCCPS2_VERSION}: tools/mwccps2/mwccps2.exe")
        return True

    print(f"[tools] baixando Metrowerks {MWCCPS2_VERSION}")

    try:
        with urllib.request.urlopen(MWCCPS2_URL, timeout=60) as response:
            payload = response.read()
    except (OSError, urllib.error.URLError) as exc:
        print(f"erro ao baixar Metrowerks: {exc}", file=sys.stderr)
        return False

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = {
                Path(member.name).name.lower(): member
                for member in archive.getmembers()
                if member.isfile()
            }

            extracted = {}
            for name in MWCCPS2_FILES:
                member = members.get(name.lower())
                if member is None:
                    print(f"arquivo ausente no pacote: {name}", file=sys.stderr)
                    return False

                source = archive.extractfile(member)
                if source is None:
                    print(f"erro ao extrair do pacote: {name}", file=sys.stderr)
                    return False

                extracted[name] = source.read()
    except tarfile.TarError as exc:
        print(f"pacote do Metrowerks invalido: {exc}", file=sys.stderr)
        return False

    try:
        destination.mkdir(parents=True, exist_ok=True)
        for name, data in extracted.items():
            (destination / name).write_bytes(data)
    except OSError as exc:
        print(f"erro ao instalar Metrowerks: {exc}", file=sys.stderr)
        return False

    print(f"[ok] Metrowerks {MWCCPS2_VERSION}: tools/mwccps2/mwccps2.exe")
    return True


def install_wibo(root: Path) -> bool:
    key = (platform.system(), platform.machine().lower())

    if key not in WIBO_ASSETS:
        print(
            f"Wibo sem instalacao automatica para: {key[0]} {key[1]}",
            file=sys.stderr,
        )
        print(
            "baixe manualmente em https://github.com/decompals/wibo/releases",
            file=sys.stderr,
        )
        return False

    asset, expected_sha = WIBO_ASSETS[key]
    destination = root / "tools/bin/wibo"

    try:
        current = destination.read_bytes()
    except FileNotFoundError:
        current = None
    except OSError as exc:
        print(f"erro ao ler Wibo: {exc}", file=sys.stderr)
        return False

    if current is not None and sha256(current) == expected_sha:
        try:
            destination.chmod(destination.stat().st_mode | 0o111)
        except OSError as exc:
            print(f"erro ao preparar Wibo: {exc}", file=sys.stderr)
            return False

        print(f"[ok] Wibo {WIBO_VERSION}: tools/bin/wibo")
        return True

    url = (
        "https://github.com/decompals/wibo/releases/download/"
        f"{WIBO_VERSION}/{asset}"
    )
    print(f"[tools] baixando Wibo {WIBO_VERSION}")

    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read()
    except (OSError, urllib.error.URLError) as exc:
        print(f"erro ao baixar Wibo: {exc}", file=sys.stderr)
        return False

    actual_sha = sha256(payload)

    if actual_sha != expected_sha:
        print(f"hash do Wibo invalido: {actual_sha}", file=sys.stderr)
        return False

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        destination.chmod(destination.stat().st_mode | 0o111)
    except OSError as exc:
        print(f"erro ao instalar Wibo: {exc}", file=sys.stderr)
        return False

    print(f"[ok] Wibo {WIBO_VERSION}: tools/bin/wibo")
    return True


def install_objdiff(root: Path) -> bool:
    key = (platform.system(), platform.machine().lower())

    if key not in OBJDIFF_ASSETS:
        print(
            f"plataforma nao suportada automaticamente: {key[0]} {key[1]}",
            file=sys.stderr,
        )
        print(
            "baixe objdiff-cli manualmente em "
            "https://github.com/encounter/objdiff/releases",
            file=sys.stderr,
        )
        return False

    asset, expected_sha = OBJDIFF_ASSETS[key]
    destination = root / "tools/objdiff-cli"

    try:
        current = destination.read_bytes()
    except FileNotFoundError:
        current = None
    except OSError as exc:
        print(f"erro ao ler objdiff: {exc}", file=sys.stderr)
        return False

    if current is not None and sha256(current) == expected_sha:
        try:
            destination.chmod(destination.stat().st_mode | 0o111)
        except OSError as exc:
            print(f"erro ao preparar objdiff: {exc}", file=sys.stderr)
            return False

        print(f"[ok] objdiff-cli {OBJDIFF_VERSION}: tools/objdiff-cli")
        return True

    url = (
        "https://github.com/encounter/objdiff/releases/download/"
        f"v{OBJDIFF_VERSION}/{asset}"
    )
    print(f"[tools] baixando objdiff-cli {OBJDIFF_VERSION}")

    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read()
    except (OSError, urllib.error.URLError) as exc:
        print(f"erro ao baixar objdiff: {exc}", file=sys.stderr)
        return False

    actual_sha = sha256(payload)

    if actual_sha != expected_sha:
        print(
            f"hash do objdiff invalido: {actual_sha}",
            file=sys.stderr,
        )
        return False

    try:
        destination.write_bytes(payload)
        destination.chmod(destination.stat().st_mode | 0o111)
    except OSError as exc:
        print(f"erro ao instalar objdiff: {exc}", file=sys.stderr)
        return False

    print(f"[ok] objdiff-cli {OBJDIFF_VERSION}: tools/objdiff-cli")
    return True


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    wibo_ok = install_wibo(root)
    objdiff_ok = install_objdiff(root)
    compiler_ok = install_compiler(root)

    if not wibo_ok or not objdiff_ok or not compiler_ok:
        return 1

    print("[ok] ferramentas prontas; use: make match FUNC=func_XXXXXXXX")
    return 0


if __name__ == "__main__":
    sys.exit(main())
