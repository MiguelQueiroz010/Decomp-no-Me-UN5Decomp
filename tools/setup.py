from pathlib import Path
import hashlib
import shutil
import subprocess
import sys

import yaml


root = Path(__file__).resolve().parents[1]

elf = root / "baserom/SLES_556.05"
rom = root / "baserom/SLES_556.05.rom"
config_file = root / "config/SLES_556.05.yaml"

elf_sha256 = "20a43677397731a2a20899336d1165ace5b436906b9b89be90fb10f4558dd19d"


def hash_file(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)

    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)

    return digest.hexdigest()


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def keep(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".gitkeep").touch()


def run(command: list[str], *, cwd: Path | None = None) -> bool:
    try:
        subprocess.run(
            command,
            cwd=cwd,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False

    return True


def main() -> int:
    if not elf.is_file():
        return fail("baserom/SLES_556.05 não encontrado")

    try:
        actual_sha256 = hash_file(elf, "sha256")
    except OSError as exc:
        return fail(f"erro ao ler o ELF: {exc}")

    if actual_sha256 != elf_sha256:
        return fail("hash do ELF incorreta")

    if not config_file.is_file():
        return fail("config/SLES_556.05.yaml não encontrado")

    objcopy = shutil.which("mips-linux-gnu-objcopy")
    splat = shutil.which("splat")

    if objcopy is None:
        return fail("mips-linux-gnu-objcopy não encontrado")

    if splat is None:
        return fail("splat não encontrado")

    try:
        with config_file.open(encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except OSError as exc:
        return fail(f"erro ao ler a configuração: {exc}")
    except yaml.YAMLError as exc:
        return fail(f"yaml inválido: {exc}")

    if not isinstance(config, dict):
        return fail("configuração inválida")

    options = config.get("options")

    if not isinstance(options, dict):
        return fail("options não encontrado na configuração")

    print("gerando rom")

    if not run(
        [
            objcopy,
            "-O",
            "binary",
            "--gap-fill=0x00",
            str(elf),
            str(rom),
        ]
    ):
        rom.unlink(missing_ok=True)
        return fail("erro ao gerar a rom")

    expected_sha1 = config.get("sha1")

    if expected_sha1 is not None:
        if not isinstance(expected_sha1, str):
            rom.unlink(missing_ok=True)
            return fail("sha1 inválido na configuração")

        try:
            actual_sha1 = hash_file(rom, "sha1")
        except OSError as exc:
            rom.unlink(missing_ok=True)
            return fail(f"erro ao verificar a rom: {exc}")

        if actual_sha1.lower() != expected_sha1.strip().lower():
            rom.unlink(missing_ok=True)
            return fail("hash da rom gerada não confere")

    for name in ("asm", "assets", "build"):
        path = root / name

        if path.exists():
            try:
                shutil.rmtree(path)
            except OSError as exc:
                return fail(f"erro ao remover {name}: {exc}")

    try:
        keep(root / "asm/cod")
        keep(root / "assets/cod")
        keep(root / "build")
        keep(root / "config/auto")
        keep(root / "tools/splat_ext")
    except OSError as exc:
        return fail(f"erro ao criar diretórios: {exc}")

    reloc = root / "config/reloc_addrs.txt"

    try:
        reloc.touch(exist_ok=True)
    except OSError as exc:
        return fail(f"erro ao criar reloc_addrs.txt: {exc}")

    options["base_path"] = str(root)
    options["target_path"] = str(rom)
    options["elf_path"] = str(root / "build/SLES_556.05.elf")

    options["asm_path"] = str(root / "asm")
    options["src_path"] = str(root / "src")
    options["build_path"] = str(root / "build")
    options["asset_path"] = str(root / "assets")

    options["ld_script_path"] = str(root / "config/SLES_556.05.ld")

    options["symbol_addrs_path"] = [
        str(root / "config/symbol_addrs.txt"),
    ]

    options["reloc_addrs_path"] = [
        str(reloc),
    ]

    options["undefined_funcs_auto_path"] = str(
        root / "config/auto/undefined_funcs_auto.txt"
    )

    options["undefined_syms_auto_path"] = str(
        root / "config/auto/undefined_syms_auto.txt"
    )

    options["extensions_path"] = str(root / "tools/splat_ext")

    temporary_config = root / "build/setup.splat.yaml"

    try:
        with temporary_config.open("w", encoding="utf-8") as f:
            yaml.safe_dump(
                config,
                f,
                sort_keys=False,
                allow_unicode=True,
            )
    except (OSError, yaml.YAMLError) as exc:
        return fail(f"erro ao gerar configuração temporária: {exc}")

    print("extraindo")

    if not run(
        [
            splat,
            "split",
            str(temporary_config),
        ],
        cwd=root,
    ):
        return fail("erro ao executar o splat")

    print("setup concluído")

    return 0


if __name__ == "__main__":
    sys.exit(main())