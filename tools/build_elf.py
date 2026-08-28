from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

from elf_object import ElfError, Section, find_section, sections


ELF_SYMBOL = struct.Struct("<IIIBBH")
ELF_RELOCATION = struct.Struct("<II")

SHT_SYMTAB = 2
SHT_REL = 9
SHF_ALLOC = 0x2

SHN_UNDEF = 0
SHN_ABS = 0xFFF1

STT_SECTION = 3

R_MIPS_NONE = 0
R_MIPS_16 = 1
R_MIPS_32 = 2
R_MIPS_26 = 4
R_MIPS_HI16 = 5
R_MIPS_LO16 = 6
R_MIPS_GPREL16 = 7
R_MIPS_PC16 = 10
R_MIPS_GPREL32 = 12

RELOCATION_NAMES = {
    R_MIPS_NONE: "R_MIPS_NONE",
    R_MIPS_16: "R_MIPS_16",
    R_MIPS_32: "R_MIPS_32",
    R_MIPS_26: "R_MIPS_26",
    R_MIPS_HI16: "R_MIPS_HI16",
    R_MIPS_LO16: "R_MIPS_LO16",
    R_MIPS_GPREL16: "R_MIPS_GPREL16",
    R_MIPS_PC16: "R_MIPS_PC16",
    R_MIPS_GPREL32: "R_MIPS_GPREL32",
}

ADDRESS_PATTERN = re.compile(
    r"^\s*([A-Za-z_.$][A-Za-z0-9_.$]*)\s*=\s*"
    r"(0x[0-9A-Fa-f]+|[0-9]+)\s*;"
)


class HybridError(RuntimeError):
    pass


@dataclass(frozen=True)
class FunctionInfo:
    name: str
    vram: int
    size: int


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    size: int
    info: int
    section_index: int

    @property
    def symbol_type(self) -> int:
        return self.info & 0xF


@dataclass(frozen=True)
class Relocation:
    offset: int
    symbol_index: int
    relocation_type: int


@dataclass(frozen=True)
class CompiledFunction:
    function: FunctionInfo
    source: Path
    object_path: Path
    text: bytes
    relocation_count: int
    placement_vram: int


@dataclass
class CodeCave:
    vram: int
    size: int
    used: int = 0

    def allocate(self, size: int, alignment: int = 16) -> int | None:
        start = (self.vram + self.used + alignment - 1) & -alignment
        end = start + size
        if end > self.vram + self.size:
            return None
        self.used = end - self.vram
        return start


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "compila os C e os injeta em uma copia do ELF original, "
            "preservando todos os outros bytes"
        )
    )
    parser.add_argument("--profile", default="mwcc24_o3p")
    parser.add_argument("--source-dir", type=Path, default=Path("src/cod"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("build/SLES_556.05.elf"),
    )
    parser.add_argument(
        "--require-match",
        action="store_true",
        help="recusa qualquer C que nao seja identico ao original",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, min(8, os.cpu_count() or 1)),
    )
    return parser.parse_args(argv)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise HybridError(f"erro ao abrir {path}") from exc
    except json.JSONDecodeError as exc:
        raise HybridError(f"JSON invalido: {path}") from exc


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def read_word(data: bytearray, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise HybridError(f"relocacao fora de .text: 0x{offset:X}")
    return struct.unpack_from("<I", data, offset)[0]


def write_word(data: bytearray, offset: int, value: int) -> None:
    if offset < 0 or offset + 4 > len(data):
        raise HybridError(f"relocacao fora de .text: 0x{offset:X}")
    struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)


def replace_immediate(word: int, immediate: int) -> int:
    return (word & 0xFFFF0000) | (immediate & 0xFFFF)


def c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise HybridError("offset de string fora do objeto")
    end = data.find(b"\0", offset)
    if end < 0:
        raise HybridError("string sem terminador no objeto")
    return data[offset:end].decode("ascii", errors="replace")


def parse_symbols(data: bytes, all_sections: list[Section]) -> list[Symbol]:
    symbol_table = next(
        (section for section in all_sections if section.section_type == SHT_SYMTAB),
        None,
    )
    if symbol_table is None:
        raise HybridError("objeto sem .symtab")
    if symbol_table.link >= len(all_sections):
        raise HybridError(".symtab aponta para string table invalida")
    entry_size = symbol_table.entry_size or ELF_SYMBOL.size
    if entry_size != ELF_SYMBOL.size:
        raise HybridError("tamanho de simbolo inesperado")
    strings = all_sections[symbol_table.link]
    strings_data = data[strings.offset:strings.offset + strings.size]
    result = []
    for offset in range(
        symbol_table.offset,
        symbol_table.offset + symbol_table.size,
        entry_size,
    ):
        name_offset, value, size, info, _other, section_index = (
            ELF_SYMBOL.unpack_from(data, offset)
        )
        name = "" if name_offset == 0 else c_string(strings_data, name_offset)
        result.append(
            Symbol(
                name=name,
                value=value,
                size=size,
                info=info,
                section_index=section_index,
            )
        )
    return result


def parse_text_relocations(
    data: bytes,
    all_sections: list[Section],
    text_section: Section,
) -> list[Relocation]:
    result = []
    for section in all_sections:
        if section.section_type != SHT_REL or section.info != text_section.index:
            continue
        entry_size = section.entry_size or ELF_RELOCATION.size
        if entry_size != ELF_RELOCATION.size:
            raise HybridError(f"tamanho de relocacao inesperado em {section.name}")
        for offset in range(section.offset, section.offset + section.size, entry_size):
            relocation_offset, info = ELF_RELOCATION.unpack_from(data, offset)
            result.append(
                Relocation(
                    offset=relocation_offset,
                    symbol_index=info >> 8,
                    relocation_type=info & 0xFF,
                )
            )
    return result


def reject_extra_runtime_sections(
    data: bytes,
    all_sections: list[Section],
    text_section: Section,
    source: Path,
) -> None:
    for section in all_sections:
        flags = struct.unpack_from("<I", data, section.header_offset + 8)[0]
        if (
            section.index != text_section.index
            and section.size > 0
            and flags & SHF_ALLOC
        ):
            raise HybridError(
                f"{source.name}: secao alocavel {section.name or section.index} "
                "ainda nao pode ser colocada no ELF hibrido"
            )


def symbol_address(
    symbol: Symbol,
    *,
    known_addresses: dict[str, int],
    text_section: Section,
    function_vram: int,
) -> int:
    if symbol.section_index == SHN_UNDEF:
        if symbol.name not in known_addresses:
            raise HybridError(f"simbolo sem endereco conhecido: {symbol.name or '<sem nome>'}")
        return known_addresses[symbol.name]
    if symbol.section_index == SHN_ABS:
        return symbol.value
    if symbol.section_index == text_section.index:
        return function_vram + symbol.value
    if symbol.symbol_type == STT_SECTION and symbol.section_index == text_section.index:
        return function_vram + symbol.value
    raise HybridError(
        f"simbolo {symbol.name or '<secao>'} pertence a uma secao nao suportada"
    )


def apply_relocations(
    text: bytes,
    relocations: list[Relocation],
    symbols: list[Symbol],
    *,
    known_addresses: dict[str, int],
    text_section: Section,
    function_vram: int,
    gp: int,
) -> bytes:
    output = bytearray(text)

    def resolved(relocation: Relocation) -> int:
        if relocation.symbol_index >= len(symbols):
            raise HybridError("indice de simbolo invalido em relocacao")
        return symbol_address(
            symbols[relocation.symbol_index],
            known_addresses=known_addresses,
            text_section=text_section,
            function_vram=function_vram,
        )

    for index, relocation in enumerate(relocations):
        relocation_type = relocation.relocation_type
        if relocation_type == R_MIPS_NONE:
            continue

        symbol_value = resolved(relocation)
        word = read_word(output, relocation.offset)

        if relocation_type == R_MIPS_32:
            write_word(output, relocation.offset, symbol_value + word)
        elif relocation_type == R_MIPS_26:
            addend = (word & 0x03FFFFFF) << 2
            target = symbol_value + addend
            place = function_vram + relocation.offset
            if (target >> 28) != ((place + 4) >> 28):
                raise HybridError(
                    f"R_MIPS_26 cruza regiao de 256 MiB: 0x{place:08X} -> 0x{target:08X}"
                )
            write_word(
                output,
                relocation.offset,
                (word & 0xFC000000) | ((target >> 2) & 0x03FFFFFF),
            )
        elif relocation_type == R_MIPS_GPREL16:
            value = symbol_value + signed16(word & 0xFFFF) - gp
            if not -0x8000 <= value <= 0x7FFF:
                raise HybridError(
                    f"R_MIPS_GPREL16 fora do alcance para 0x{symbol_value:08X}"
                )
            write_word(output, relocation.offset, replace_immediate(word, value))
        elif relocation_type == R_MIPS_GPREL32:
            write_word(output, relocation.offset, symbol_value + word - gp)
        elif relocation_type == R_MIPS_HI16:
            matching_lo = next(
                (
                    candidate
                    for candidate in relocations[index + 1:]
                    if candidate.symbol_index == relocation.symbol_index
                    and candidate.relocation_type == R_MIPS_LO16
                ),
                None,
            )
            if matching_lo is None:
                raise HybridError("R_MIPS_HI16 sem R_MIPS_LO16 correspondente")
            lo_word = read_word(output, matching_lo.offset)
            addend = ((word & 0xFFFF) << 16) + signed16(lo_word & 0xFFFF)
            value = symbol_value + addend
            high = (value + 0x8000) >> 16
            write_word(output, relocation.offset, replace_immediate(word, high))
        elif relocation_type == R_MIPS_LO16:
            value = symbol_value + signed16(word & 0xFFFF)
            write_word(output, relocation.offset, replace_immediate(word, value))
        elif relocation_type == R_MIPS_16:
            value = symbol_value + signed16(word & 0xFFFF)
            if not -0x8000 <= value <= 0xFFFF:
                raise HybridError("R_MIPS_16 fora do alcance")
            write_word(output, relocation.offset, replace_immediate(word, value))
        elif relocation_type == R_MIPS_PC16:
            addend = signed16(word & 0xFFFF) << 2
            place = function_vram + relocation.offset
            delta = symbol_value + addend - (place + 4)
            if delta & 3 or not -0x20000 <= delta <= 0x1FFFC:
                raise HybridError("R_MIPS_PC16 fora do alcance")
            write_word(output, relocation.offset, replace_immediate(word, delta >> 2))
        else:
            name = RELOCATION_NAMES.get(relocation_type, f"tipo {relocation_type}")
            raise HybridError(f"relocacao ainda nao suportada: {name}")

    return bytes(output)


def read_inventory(path: Path) -> dict[str, FunctionInfo]:
    raw = load_json(path).get("functions")
    if not isinstance(raw, list):
        raise HybridError("inventario de funcoes invalido")
    result = {}
    for item in raw:
        try:
            name = item["name"]
            vram = int(item["vram"], 0)
            size = item["size"]
        except (KeyError, TypeError, ValueError) as exc:
            raise HybridError("entrada invalida no inventario") from exc
        if not isinstance(name, str) or not isinstance(size, int) or size <= 0:
            raise HybridError("entrada invalida no inventario")
        result[name] = FunctionInfo(name=name, vram=vram, size=size)
    return result


def read_address_file(path: Path) -> dict[str, int]:
    if not path.is_file():
        return {}
    result = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        raise HybridError(f"erro ao ler {path}") from exc
    for line in lines:
        match = ADDRESS_PATTERN.match(line)
        if match is not None:
            result[match.group(1)] = int(match.group(2), 0)
    return result


def known_symbol_addresses(
    root: Path,
    inventory: dict[str, FunctionInfo],
    gp: int,
) -> dict[str, int]:
    result = {name: function.vram for name, function in inventory.items()}
    for relative in (
        "config/symbol_addrs.txt",
        "config/auto/undefined_funcs_auto.txt",
        "config/auto/undefined_syms_auto.txt",
    ):
        result.update(read_address_file(root / relative))
    result["_gp"] = gp
    return result


def resolve_tool(root: Path, value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    local = root / path
    return str(local) if local.exists() else value


def compile_source(
    source: Path,
    *,
    root: Path,
    object_dir: Path,
    wibo: str,
    mwcc: str,
    flags: list[str],
) -> tuple[Path, Path, subprocess.CompletedProcess[str]]:
    object_path = object_dir / f"{source.stem}.o"
    command = [wibo, mwcc, "-c", *flags, "-o", str(object_path), str(source)]
    try:
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        raise HybridError(f"erro ao executar {command[0]}: {exc}") from exc
    return source, object_path, result


def prepare_compiled_function(
    source: Path,
    object_path: Path,
    *,
    inventory: dict[str, FunctionInfo],
    addresses: dict[str, int],
    gp: int,
    placement_vram: int | None = None,
) -> CompiledFunction:
    if source.stem not in inventory:
        raise HybridError(f"funcao fora do inventario: {source.stem}")
    function = inventory[source.stem]
    if placement_vram is None:
        placement_vram = function.vram
    try:
        data = object_path.read_bytes()
        all_sections = sections(data)
        text_section = find_section(data, ".text")
        reject_extra_runtime_sections(data, all_sections, text_section, source)
        symbols = parse_symbols(data, all_sections)
        relocations = parse_text_relocations(data, all_sections, text_section)
        raw_text = data[text_section.offset:text_section.offset + text_section.size]
        relocated_text = apply_relocations(
            raw_text,
            relocations,
            symbols,
            known_addresses=addresses,
            text_section=text_section,
            function_vram=placement_vram,
            gp=gp,
        )
    except (OSError, ElfError, HybridError) as exc:
        raise HybridError(f"{source.name}: {exc}") from exc
    if not relocated_text:
        raise HybridError(f"{source.name}: .text vazia")
    return CompiledFunction(
        function=function,
        source=source,
        object_path=object_path,
        text=relocated_text,
        relocation_count=len(relocations),
        placement_vram=placement_vram,
    )


def read_code_caves(config: dict) -> list[CodeCave]:
    raw = config.get("code_caves", [])
    if not isinstance(raw, list):
        raise HybridError("lista de code caves invalida")
    caves = []
    for item in raw:
        try:
            vram = int(item["vram"], 0)
            size = int(item["size"], 0)
        except (KeyError, TypeError, ValueError) as exc:
            raise HybridError("code cave invalido") from exc
        if vram & 3 or size <= 0 or size & 3:
            raise HybridError("code cave deve ter endereco e tamanho alinhados a 4")
        caves.append(CodeCave(vram=vram, size=size))
    return caves


def encode_jump(source_vram: int, target_vram: int) -> bytes:
    if (target_vram >> 28) != ((source_vram + 4) >> 28):
        raise HybridError(
            f"trampolim cruza regiao de 256 MiB: "
            f"0x{source_vram:08X} -> 0x{target_vram:08X}"
        )
    instruction = 0x08000000 | ((target_vram >> 2) & 0x03FFFFFF)
    return struct.pack("<II", instruction, 0)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    source_dir = args.source_dir if args.source_dir.is_absolute() else root / args.source_dir
    output = args.output if args.output.is_absolute() else root / args.output

    try:
        config = load_json(root / "config/decomp.json")
        profiles = load_json(root / "config/compiler_profiles.json")
        if args.profile not in profiles or not isinstance(profiles[args.profile], list):
            raise HybridError(f"perfil invalido: {args.profile}")
        base = config["base"]
        tools = config["tools"]
        base_elf_path = root / base["elf"]
        expected_sha = base["elf_sha256"]
        load_vram = int(base["load_vram"], 0)
        file_backed_size = int(base["file_backed_size"], 0)
        elf_file_offset = int(base["elf_file_offset"], 0)
        gp = int(config.get("gp", "0x00617EF0"), 0)
        inventory = read_inventory(root / "progress/functions.json")
        addresses = known_symbol_addresses(root, inventory, gp)
        code_caves = read_code_caves(config)
    except (KeyError, TypeError, ValueError, HybridError) as exc:
        print(f"erro de configuracao: {exc}", file=sys.stderr)
        return 2

    if not base_elf_path.is_file():
        print("ELF original nao encontrado; rode make setup", file=sys.stderr)
        return 2
    if not source_dir.is_dir():
        print(f"diretorio de C nao encontrado: {source_dir}", file=sys.stderr)
        return 2

    try:
        base_elf = base_elf_path.read_bytes()
    except OSError as exc:
        print(f"erro ao ler ELF original: {exc}", file=sys.stderr)
        return 2
    if sha256(base_elf) != expected_sha:
        print("hash do ELF original nao confere", file=sys.stderr)
        return 2
    if elf_file_offset + file_backed_size > len(base_elf):
        print("segmento original ultrapassa o arquivo ELF", file=sys.stderr)
        return 2

    for cave in code_caves:
        segment_offset = cave.vram - load_vram
        if segment_offset < 0 or segment_offset + cave.size > file_backed_size:
            print(
                f"code cave fora do segmento: 0x{cave.vram:08X}",
                file=sys.stderr,
            )
            return 2
        cave_start = elf_file_offset + segment_offset
        cave_bytes = base_elf[cave_start:cave_start + cave.size]
        if any(cave_bytes):
            print(
                f"code cave nao esta zerado no ELF original: 0x{cave.vram:08X}",
                file=sys.stderr,
            )
            return 2
        cave_end = cave.vram + cave.size
        overlapping = [
            function.name
            for function in inventory.values()
            if function.vram < cave_end
            and function.vram + function.size > cave.vram
        ]
        if overlapping:
            print(
                f"code cave sobrepoe funcao: {', '.join(overlapping)}",
                file=sys.stderr,
            )
            return 2

    sources = sorted(source_dir.rglob("func_*.c"))
    if not sources:
        print("nenhum src/cod/func_*.c encontrado", file=sys.stderr)
        return 2
    duplicate_names = sorted(
        name
        for name in {source.stem for source in sources}
        if sum(source.stem == name for source in sources) > 1
    )
    if duplicate_names:
        print(f"fontes duplicadas: {', '.join(duplicate_names)}", file=sys.stderr)
        return 2

    object_dir = root / "build/elf/obj"
    object_dir.mkdir(parents=True, exist_ok=True)
    try:
        wibo = resolve_tool(root, os.environ.get("WIBO", tools["wibo"]))
        mwcc = resolve_tool(root, tools["mwcc"])
    except KeyError:
        print("ferramentas nao configuradas", file=sys.stderr)
        return 2

    print(f"compilando {len(sources)} funcoes C ({args.profile})")
    try:
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
            compiled_results = list(
                executor.map(
                    lambda source: compile_source(
                        source,
                        root=root,
                        object_dir=object_dir,
                        wibo=wibo,
                        mwcc=mwcc,
                        flags=profiles[args.profile],
                    ),
                    sources,
                )
            )
    except HybridError as exc:
        print(exc, file=sys.stderr)
        return 2

    compile_failures = []
    for source, _object_path, result in compiled_results:
        if result.returncode != 0:
            details = (result.stderr or result.stdout).strip()
            compile_failures.append(f"{source.name}: {details or 'erro do compilador'}")
    if compile_failures:
        print("falha ao compilar:", file=sys.stderr)
        for failure in compile_failures:
            print(f"  {failure}", file=sys.stderr)
        return 2

    compiled_functions = []
    try:
        for source, object_path, _result in compiled_results:
            compiled = prepare_compiled_function(
                source,
                object_path,
                inventory=inventory,
                addresses=addresses,
                gp=gp,
            )
            if len(compiled.text) > compiled.function.size:
                if compiled.function.size < 8:
                    raise HybridError(
                        f"{source.name}: slot de {compiled.function.size} bytes "
                        "nao comporta um trampolim"
                    )
                placement_vram = next(
                    (
                        allocated
                        for cave in code_caves
                        if (allocated := cave.allocate(len(compiled.text))) is not None
                    ),
                    None,
                )
                if placement_vram is None:
                    raise HybridError(
                        f"{source.name}: codigo compilado tem {len(compiled.text)} "
                        f"bytes, o slot tem {compiled.function.size} e nenhum "
                        "code cave configurado comporta a funcao"
                    )
                compiled = prepare_compiled_function(
                    source,
                    object_path,
                    inventory=inventory,
                    addresses=addresses,
                    gp=gp,
                    placement_vram=placement_vram,
                )
            compiled_functions.append(compiled)
    except HybridError as exc:
        print(exc, file=sys.stderr)
        return 2

    hybrid = bytearray(base_elf)
    report_functions = []
    exact_count = 0
    modified_count = 0
    relocation_count = 0
    padded_count = 0
    code_cave_count = 0

    for compiled in compiled_functions:
        function = compiled.function
        source_label = (
            compiled.source.relative_to(root)
            if compiled.source.is_relative_to(root)
            else compiled.source
        )
        segment_offset = function.vram - load_vram
        if (
            segment_offset < 0
            or segment_offset + function.size > file_backed_size
        ):
            print(f"{function.name}: endereco fora do segmento", file=sys.stderr)
            return 2
        file_offset = elf_file_offset + segment_offset
        original = base_elf[file_offset:file_offset + function.size]
        relocated = compiled.placement_vram != function.vram
        if relocated:
            patched = encode_jump(function.vram, compiled.placement_vram)
            patched += b"\0" * (function.size - len(patched))
            exact = False
        else:
            patched = compiled.text + b"\0" * (function.size - len(compiled.text))
            exact = patched == original
        if args.require_match and not exact:
            print(
                f"{function.name}: nao e match exato; "
                "remova STRICT=1 para gerar um ELF modificado",
                file=sys.stderr,
            )
            return 1
        hybrid[file_offset:file_offset + function.size] = patched
        if relocated:
            cave_segment_offset = compiled.placement_vram - load_vram
            cave_file_offset = elf_file_offset + cave_segment_offset
            hybrid[
                cave_file_offset:cave_file_offset + len(compiled.text)
            ] = compiled.text
        exact_count += int(exact)
        modified_count += int(not exact)
        relocation_count += compiled.relocation_count
        padded_count += int(not relocated and len(compiled.text) < function.size)
        code_cave_count += int(relocated)
        report_functions.append(
            {
                "name": function.name,
                "source": str(source_label),
                "vram": f"0x{function.vram:08X}",
                "slot_size": function.size,
                "compiled_size": len(compiled.text),
                "padding_size": (
                    function.size - len(compiled.text) if not relocated else 0
                ),
                "relocations": compiled.relocation_count,
                "exact": exact,
                "relocated": relocated,
                "placement_vram": f"0x{compiled.placement_vram:08X}",
            }
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output.with_suffix(output.suffix + ".tmp")
    try:
        temporary_output.write_bytes(hybrid)
        temporary_output.chmod(base_elf_path.stat().st_mode)
        temporary_output.replace(output)
    except OSError as exc:
        temporary_output.unlink(missing_ok=True)
        print(f"erro ao gravar ELF hibrido: {exc}", file=sys.stderr)
        return 2

    report = {
        "format": 1,
        "base_elf": str(base_elf_path.relative_to(root)),
        "output_elf": (
            str(output.relative_to(root))
            if output.is_relative_to(root)
            else str(output)
        ),
        "profile": args.profile,
        "base_sha256": sha256(base_elf),
        "output_sha256": sha256(hybrid),
        "compiled_functions": len(compiled_functions),
        "exact_functions": exact_count,
        "modified_functions": modified_count,
        "padded_functions": padded_count,
        "code_cave_functions": code_cave_count,
        "applied_relocations": relocation_count,
        "functions": report_functions,
    }
    report_path = root / "build/elf/report.json"
    try:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"erro ao gravar relatorio: {exc}", file=sys.stderr)
        return 2

    output_label = output.relative_to(root) if output.is_relative_to(root) else output
    modified_names = [
        function["name"]
        for function in report_functions
        if not function["exact"]
    ]
    print(f"ELF gerado: {output_label}")
    print(f"funcoes C: {len(compiled_functions)}")
    print(f"identicas: {exact_count}")
    print(f"modificadas: {modified_count}")
    if modified_names:
        print(f"lista modificada: {', '.join(modified_names)}")
    print(f"com padding: {padded_count}")
    print(f"em code cave: {code_cave_count}")
    print(f"relocacoes aplicadas: {relocation_count}")
    print(f"sha256: {sha256(hybrid)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
