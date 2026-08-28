from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

from build_elf import (
    HybridError,
    known_symbol_addresses,
    prepare_compiled_function,
    read_inventory,
)
from elf_object import ElfError, replace_section
from progress import ProgressError, generate_report, invalidate_match, record_match


EXIT_MATCH = 0
EXIT_MISMATCH = 1
EXIT_ERROR = 2
FUNCTION_PATTERN = re.compile(r"^func_([0-9A-Fa-f]{8})$")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("profile")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument(
        "--prepare-objdiff",
        action="store_true",
        help=(
            "gera os objetos atual e esperado para o objdiff e retorna 0 "
            "mesmo quando os bytes ainda nao combinam"
        ),
    )
    parser.add_argument(
        "--objdiff",
        action="store_true",
        help="prepara os dois objetos, mostra o objdiff e valida o match",
    )
    return parser.parse_args(argv)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuntimeError(f"erro ao abrir {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"json invalido: {path}") from exc


def function_vram(source: Path) -> int:
    match = FUNCTION_PATTERN.fullmatch(source.stem)
    if match is None:
        raise ValueError("nome de funcao invalido")
    return int(match.group(1), 16)


def function_size(root: Path, name: str) -> int:
    inventory_path = root / "progress/functions.json"
    if inventory_path.is_file():
        inventory = load_json(inventory_path)
        functions = inventory.get("functions")
        if isinstance(functions, list):
            for function in functions:
                if (
                    isinstance(function, dict)
                    and function.get("name") == name
                    and isinstance(function.get("size"), int)
                    and function["size"] > 0
                ):
                    return function["size"]

    pattern = re.compile(
        rf"^\s*nonmatching\s+{re.escape(name)}\s*,\s*(0x[0-9A-Fa-f]+|\d+)"
    )

    for asm_file in (root / "asm/cod/text.s", root / "asm/cod/late_text.s"):
        if not asm_file.is_file():
            continue
        try:
            with asm_file.open(encoding="utf-8", errors="ignore") as file:
                for line in file:
                    match = pattern.match(line)
                    if match is None:
                        continue
                    size = int(match.group(1), 0)
                    if size <= 0:
                        raise RuntimeError(f"tamanho invalido para {name}")
                    return size
        except OSError as exc:
            raise RuntimeError(f"erro ao ler {asm_file}") from exc

    raise RuntimeError(f"tamanho de {name} nao encontrado no asm")


def resolve_tool(root: Path, value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    local = root / path
    return str(local) if local.exists() else value


def run_command(cmd: list[str], root: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    except OSError as exc:
        raise RuntimeError(f"erro ao executar {cmd[0]}: {exc}") from exc


def first_mismatch(original: bytes, compiled: bytes) -> int | None:
    for offset, (expected, actual) in enumerate(zip(original, compiled)):
        if expected != actual:
            return offset
    if len(original) != len(compiled):
        return min(len(original), len(compiled))
    return None


def format_bytes(data: bytes) -> str:
    return data.hex(" ").upper() if data else "<missing>"


def instruction_diff(
    original: bytes,
    compiled: bytes,
    mismatch: int,
    vram: int,
) -> dict:
    offset = mismatch & ~3
    return {
        "offset": offset,
        "vram": vram + offset,
        "expected": format_bytes(original[offset : offset + 4]),
        "actual": format_bytes(compiled[offset : offset + 4]),
    }


def matching_stats(original: bytes, compiled: bytes) -> tuple[int, int, float]:
    same = sum(
        expected == actual
        for expected, actual in zip(original, compiled)
    )
    total = max(len(original), len(compiled))
    percent = 100.0 if total == 0 else same / total * 100
    return same, total, percent


def reported_percent(percent: float, exact: bool, decimals: int) -> float:
    if exact:
        return 100.0
    return min(round(percent, decimals), 100.0 - 10 ** -decimals)


def print_verbose(
    *,
    source: Path,
    vram: int,
    rom_offset: int,
    size: int,
    profile: str,
    text_size: int,
    relocation_count: int,
    same: int,
    total: int,
    percent: float,
    exact: bool,
    diff: dict | None,
) -> None:
    print(f"source:      {source}")
    print(f"vram:        0x{vram:08X}")
    print(f"rom:         0x{rom_offset:08X}")
    print(f"size:        {size}")
    print(f"profile:     {profile}")
    print(f".text:       {text_size} bytes")
    print(f"relocations: {relocation_count}")
    shown_percent = reported_percent(percent, exact, 2)
    print(f"matching:    {same}/{total} ({shown_percent:.2f}%)")

    if diff is not None:
        print()
        print(f"first mismatch: +0x{diff['offset']:X}")
        print(f"address:        0x{diff['vram']:08X}")
        print(f"expected:       {diff['expected']}")
        print(f"actual:         {diff['actual']}")


def prepare_expected_object(
    object_bytes: bytes,
    original: bytes,
    name: str,
    destination: Path,
) -> None:
    expected_bytes = replace_section(
        object_bytes,
        ".text",
        original,
        symbol_name=name,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(expected_bytes)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    source = args.source

    if not source.is_absolute():
        source = root / source
    source = source.resolve()

    if not source.is_file():
        print("arquivo fonte nao encontrado", file=sys.stderr)
        return EXIT_ERROR

    name = source.stem

    try:
        vram = function_vram(source)
        size = function_size(root, name)
        config = load_json(root / "config/decomp.json")
        profiles = load_json(root / "config/compiler_profiles.json")
        inventory = read_inventory(root / "progress/functions.json")
    except (RuntimeError, ValueError, HybridError) as exc:
        print(exc, file=sys.stderr)
        return EXIT_ERROR

    if args.profile not in profiles:
        print("perfil invalido", file=sys.stderr)
        return EXIT_ERROR

    try:
        base = config["base"]
        tools = config["tools"]
        elf = root / base["elf"]
        rom = root / base["rom"]
        expected_sha = base["elf_sha256"]
        load_vram = int(base["load_vram"], 0)
        file_backed_size = int(base["file_backed_size"], 0)
        gp = int(config.get("gp", "0x00617EF0"), 0)
    except (KeyError, TypeError, ValueError):
        print("configuracao invalida", file=sys.stderr)
        return EXIT_ERROR

    function = inventory.get(name)
    if function is None:
        print("funcao fora do inventario", file=sys.stderr)
        return EXIT_ERROR
    if function.vram != vram or function.size != size:
        print("inventario de funcao inconsistente", file=sys.stderr)
        return EXIT_ERROR

    if not elf.is_file():
        print("elf base nao encontrado", file=sys.stderr)
        return EXIT_ERROR
    if not rom.is_file():
        print("rom base nao encontrada", file=sys.stderr)
        return EXIT_ERROR

    try:
        sha = hashlib.sha256(elf.read_bytes()).hexdigest()
    except OSError as exc:
        print(f"erro ao ler elf: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if sha != expected_sha:
        print("elf base diferente", file=sys.stderr)
        return EXIT_ERROR

    rom_offset = vram - load_vram
    if rom_offset < 0 or rom_offset + size > file_backed_size:
        print("endereco fora da rom", file=sys.stderr)
        return EXIT_ERROR

    try:
        with rom.open("rb") as file:
            file.seek(rom_offset)
            original = file.read(size)
    except OSError as exc:
        print(f"erro ao ler rom: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if len(original) != size:
        print("nao foi possivel ler a funcao inteira da rom", file=sys.stderr)
        return EXIT_ERROR

    out = root / "build" / "match" / name / args.profile
    out.mkdir(parents=True, exist_ok=True)
    obj = out / f"{name}.o"
    text = out / f"{name}.bin"

    prepare_objdiff = args.prepare_objdiff or args.objdiff
    expected_obj = None
    if prepare_objdiff:
        expected_obj = root / "build" / "expected" / name / args.profile / f"{name}.o"

    try:
        wibo = resolve_tool(root, os.environ.get("WIBO", tools["wibo"]))
        mwcc = resolve_tool(root, tools["mwcc"])
        objdiff = resolve_tool(root, tools["objdiff"]) if args.objdiff else None
    except KeyError:
        print("ferramentas nao configuradas", file=sys.stderr)
        return EXIT_ERROR

    if objdiff is not None and shutil.which(objdiff) is None:
        print("objdiff nao encontrado; rode: make tools", file=sys.stderr)
        return EXIT_ERROR

    command = [
        wibo,
        mwcc,
        "-c",
        *profiles[args.profile],
        "-o",
        str(obj),
        str(source),
    ]

    try:
        result = run_command(command, root)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return EXIT_ERROR

    if result.returncode != 0:
        print("erro ao compilar", file=sys.stderr)
        if result.stdout.strip():
            print(result.stdout.rstrip(), file=sys.stderr)
        if result.stderr.strip():
            print(result.stderr.rstrip(), file=sys.stderr)
        return EXIT_ERROR

    try:
        addresses = known_symbol_addresses(root, inventory, gp)
        compiled_function = prepare_compiled_function(
            source,
            obj,
            inventory=inventory,
            addresses=addresses,
            gp=gp,
            placement_vram=vram,
        )
        compiled = compiled_function.text
        object_bytes = obj.read_bytes()
        text.write_bytes(compiled)
        if expected_obj is not None:
            prepare_expected_object(object_bytes, original, name, expected_obj)
    except (OSError, ElfError, HybridError) as exc:
        print(f"erro ao preparar objetos: {exc}", file=sys.stderr)
        return EXIT_ERROR

    exact = compiled == original
    same, total, percent = matching_stats(original, compiled)
    mismatch = first_mismatch(original, compiled)
    diff = (
        instruction_diff(original, compiled, mismatch, vram)
        if mismatch is not None
        else None
    )

    source_display = source.relative_to(root) if source.is_relative_to(root) else source

    if args.json_output:
        output = {
            "function": name,
            "source": str(source_display),
            "vram": f"0x{vram:08X}",
            "rom_offset": f"0x{rom_offset:X}",
            "size": size,
            "profile": args.profile,
            "text_size": len(compiled),
            "relocations": compiled_function.relocation_count,
            "compiled_object": str(obj.relative_to(root)),
            "expected_object": (
                str(expected_obj.relative_to(root))
                if expected_obj is not None
                else None
            ),
            "matching_bytes": same,
            "matching_percent": reported_percent(percent, exact, 4),
            "exact": exact,
            "first_mismatch": None,
        }

        if diff is not None:
            output["first_mismatch"] = {
                "offset": diff["offset"],
                "address": f"0x{diff['vram']:08X}",
                "expected": diff["expected"],
                "actual": diff["actual"],
            }

        print(json.dumps(output, indent=2))
    elif args.verbose:
        print_verbose(
            source=source_display,
            vram=vram,
            rom_offset=rom_offset,
            size=size,
            profile=args.profile,
            text_size=len(compiled),
            relocation_count=compiled_function.relocation_count,
            same=same,
            total=total,
            percent=percent,
            exact=exact,
            diff=diff,
        )
    else:
        shown_percent = reported_percent(percent, exact, 2)
        print(f"matching: {shown_percent:.2f}%")
        if diff is not None:
            print(
                f"first mismatch: 0x{diff['vram']:08X} "
                f"({diff['expected']} != {diff['actual']})"
            )

    if objdiff is not None and expected_obj is not None:
        objdiff_report = out / f"{name}.objdiff.json"
        objdiff_command = [
            objdiff,
            "diff",
            "-1",
            str(expected_obj),
            "-2",
            str(obj),
            "-o",
            str(objdiff_report),
            "--format",
            "json-pretty",
            name,
        ]
        try:
            result = subprocess.run(objdiff_command, cwd=root)
        except OSError as exc:
            print(f"erro ao executar objdiff: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if not args.json_output:
            print(f"objdiff: {objdiff_report.relative_to(root)}")
        if result.returncode != 0:
            print(
                f"objdiff terminou com codigo {result.returncode}",
                file=sys.stderr,
            )
            return EXIT_ERROR

    try:
        if exact:
            record_match(
                root,
                name=name,
                source=source,
                profile=args.profile,
                vram=vram,
                original=original,
                compiled=compiled,
            )
        else:
            invalidate_match(root, name)
        matched_count, total_count, code_percent = generate_report(root, write=True)
    except ProgressError as exc:
        print(f"erro ao atualizar progresso: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.json_output:
        print(
            f"project progress: {matched_count}/{total_count} functions; "
            f"{code_percent:.6f}% code"
        )

    if args.prepare_objdiff:
        return EXIT_MATCH
    return EXIT_MATCH if exact else EXIT_MISMATCH


if __name__ == "__main__":
    sys.exit(main())
