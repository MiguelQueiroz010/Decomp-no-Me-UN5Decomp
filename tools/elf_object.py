from __future__ import annotations

from dataclasses import dataclass
import struct


ELF_HEADER = struct.Struct("<16sHHIIIIIHHHHHH")
SECTION_HEADER = struct.Struct("<IIIIIIIIII")
SYMBOL = struct.Struct("<IIIBBH")

SHT_SYMTAB = 2
STT_FUNC = 2


class ElfError(RuntimeError):
    pass


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    header_offset: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int
    section_type: int


def _c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise ElfError("offset de string fora do ELF")

    end = data.find(b"\0", offset)

    if end < 0:
        raise ElfError("string sem terminador no ELF")

    return data[offset:end].decode("ascii", errors="replace")


def sections(data: bytes) -> list[Section]:
    if len(data) < ELF_HEADER.size:
        raise ElfError("arquivo menor que o cabecalho ELF")

    header = ELF_HEADER.unpack_from(data)
    ident = header[0]

    if ident[:4] != b"\x7fELF":
        raise ElfError("arquivo nao e ELF")

    if ident[4] != 1 or ident[5] != 1:
        raise ElfError("esperado ELF32 little-endian")

    machine = header[2]
    section_offset = header[6]
    section_entry_size = header[11]
    section_count = header[12]
    string_section_index = header[13]

    if machine != 8:
        raise ElfError("esperado objeto MIPS")

    if section_entry_size != SECTION_HEADER.size:
        raise ElfError("tamanho de section header inesperado")

    table_end = section_offset + section_entry_size * section_count

    if section_offset <= 0 or table_end > len(data):
        raise ElfError("tabela de secoes fora do ELF")

    if string_section_index >= section_count:
        raise ElfError("indice de .shstrtab invalido")

    raw_headers = [
        SECTION_HEADER.unpack_from(
            data,
            section_offset + index * section_entry_size,
        )
        for index in range(section_count)
    ]

    string_header = raw_headers[string_section_index]
    string_offset = string_header[4]
    string_size = string_header[5]

    if string_offset + string_size > len(data):
        raise ElfError(".shstrtab fora do ELF")

    result = []

    for index, raw in enumerate(raw_headers):
        name_offset = raw[0]
        name = "" if name_offset == 0 else _c_string(
            data,
            string_offset + name_offset,
        )
        offset = raw[4]
        size = raw[5]

        if raw[1] != 8 and offset + size > len(data):
            raise ElfError(f"secao {name or index} fora do ELF")

        result.append(
            Section(
                index=index,
                name=name,
                header_offset=(
                    section_offset + index * section_entry_size
                ),
                offset=offset,
                size=size,
                link=raw[6],
                info=raw[7],
                alignment=raw[8],
                entry_size=raw[9],
                section_type=raw[1],
            )
        )

    return result


def find_section(data: bytes, name: str) -> Section:
    for section in sections(data):
        if section.name == name:
            return section

    raise ElfError(f"secao {name} nao encontrada")


def section_data(data: bytes, name: str) -> bytes:
    section = find_section(data, name)
    return data[section.offset : section.offset + section.size]


def _align(value: int, alignment: int) -> int:
    alignment = max(1, alignment)
    return (value + alignment - 1) // alignment * alignment


def replace_section(
    data: bytes,
    name: str,
    payload: bytes,
    *,
    symbol_name: str | None = None,
) -> bytes:
    all_sections = sections(data)
    target = next(
        (section for section in all_sections if section.name == name),
        None,
    )

    if target is None:
        raise ElfError(f"secao {name} nao encontrada")

    output = bytearray(data)
    new_offset = _align(len(output), target.alignment)
    output.extend(b"\0" * (new_offset - len(output)))
    output.extend(payload)

    struct.pack_into(
        "<II",
        output,
        target.header_offset + 16,
        new_offset,
        len(payload),
    )

    if symbol_name is not None:
        _resize_function_symbol(
            output,
            all_sections,
            target.index,
            symbol_name,
            len(payload),
        )

    return bytes(output)


def _resize_function_symbol(
    data: bytearray,
    all_sections: list[Section],
    text_index: int,
    symbol_name: str,
    size: int,
) -> None:
    for section in all_sections:
        if section.section_type != SHT_SYMTAB:
            continue

        if section.link >= len(all_sections):
            raise ElfError("symtab aponta para strtab invalida")

        entry_size = section.entry_size or SYMBOL.size

        if entry_size != SYMBOL.size:
            raise ElfError("tamanho de simbolo ELF inesperado")

        strings = all_sections[section.link]
        strings_data = bytes(
            data[strings.offset : strings.offset + strings.size]
        )

        for offset in range(
            section.offset,
            section.offset + section.size,
            entry_size,
        ):
            raw = SYMBOL.unpack_from(data, offset)
            name_offset = raw[0]
            symbol_type = raw[3] & 0xF
            section_index = raw[5]

            if name_offset >= len(strings_data):
                continue

            current_name = _c_string(strings_data, name_offset)

            if (
                current_name == symbol_name
                and symbol_type == STT_FUNC
                and section_index == text_index
            ):
                struct.pack_into("<I", data, offset + 8, size)
                return

    raise ElfError(f"simbolo {symbol_name} nao encontrado no objeto")
