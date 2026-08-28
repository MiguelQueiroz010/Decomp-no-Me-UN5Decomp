from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from pathlib import Path


FORMAT_VERSION = 1
TARGET = "SLES_556.05"
INVENTORY_PATH = Path("progress/functions.json")
REPORT_PATH = Path("progress/report.json")
CODE_BADGE_PATH = Path("progress/code.svg")
FUNCTIONS_BADGE_PATH = Path("progress/functions.svg")
PROOFS_PATH = Path("progress/matches")

DIRECTIVE_RE = re.compile(
    r"^\s*nonmatching\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*,\s*(0x[0-9A-Fa-f]+|\d+))?\s*$"
)
ADDRESS_RE = re.compile(r"/\*\s*[0-9A-Fa-f]+\s+([0-9A-Fa-f]{8})\s+")
FUNCTION_RE = re.compile(r"^func_([0-9A-Fa-f]{8})$")


class ProgressError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    try:
        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ProgressError(f"erro ao ler {path}: {exc}") from exc

    return digest.hexdigest()


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProgressError(f"erro ao ler {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProgressError(f"json invalido: {path}: {exc}") from exc


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def write_if_changed(path: Path, data: bytes) -> bool:
    try:
        if path.is_file() and path.read_bytes() == data:
            return False

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError as exc:
        raise ProgressError(f"erro ao escrever {path}: {exc}") from exc

    return True


def infer_unsized_function(lines: list[str], start: int, name: str, vram: int) -> int:
    end_markers = {f"endlabel {name}", f"enddlabel {name}"}
    last_address = None

    for line in lines[start + 1 :]:
        if line.strip() in end_markers:
            break

        match = ADDRESS_RE.search(line)
        if match:
            last_address = int(match.group(1), 16)
    else:
        raise ProgressError(f"fim de {name} nao encontrado no asm")

    if last_address is None or last_address < vram:
        raise ProgressError(f"tamanho de {name} nao encontrado no asm")

    return last_address + 4 - vram


def scan_asm(root: Path) -> list[dict[str, object]]:
    functions: list[dict[str, object]] = []
    seen: set[str] = set()

    for relative_path in ("asm/cod/text.s", "asm/cod/late_text.s"):
        asm_path = root / relative_path

        if not asm_path.is_file():
            raise ProgressError(f"{relative_path} nao encontrado; rode make setup")

        try:
            lines = asm_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError as exc:
            raise ProgressError(f"erro ao ler {asm_path}: {exc}") from exc

        for line_number, line in enumerate(lines):
            match = DIRECTIVE_RE.match(line)
            if not match:
                continue

            name, raw_size = match.groups()
            address_match = FUNCTION_RE.match(name)

            if name != "_start" and not address_match:
                continue

            if name in seen:
                raise ProgressError(f"funcao duplicada no asm: {name}")

            vram = 0x00100008 if name == "_start" else int(address_match.group(1), 16)
            size = (
                int(raw_size, 0)
                if raw_size is not None
                else infer_unsized_function(lines, line_number, name, vram)
            )

            if size <= 0 or size % 4:
                raise ProgressError(f"tamanho invalido para {name}: {size}")

            seen.add(name)
            functions.append({"name": name, "vram": f"0x{vram:08X}", "size": size})

    if not functions:
        raise ProgressError("nenhuma funcao encontrada no asm")

    functions.sort(key=lambda function: int(str(function["vram"]), 0))
    return functions


def inventory_document(functions: list[dict[str, object]]) -> dict[str, object]:
    return {"format": FORMAT_VERSION, "target": TARGET, "functions": functions}


def update_inventory(root: Path) -> list[dict[str, object]]:
    functions = scan_asm(root)
    write_if_changed(root / INVENTORY_PATH, json_bytes(inventory_document(functions)))
    return functions


def load_inventory(root: Path) -> list[dict[str, object]]:
    document = read_json(root / INVENTORY_PATH)

    if not isinstance(document, dict):
        raise ProgressError("inventario de funcoes invalido")

    functions = document.get("functions")
    if (
        document.get("format") != FORMAT_VERSION
        or document.get("target") != TARGET
        or not isinstance(functions, list)
    ):
        raise ProgressError("inventario de funcoes invalido")

    seen: set[str] = set()

    for function in functions:
        if not isinstance(function, dict):
            raise ProgressError("entrada invalida no inventario")

        name = function.get("name")
        vram = function.get("vram")
        size = function.get("size")

        if not isinstance(name, str):
            raise ProgressError("funcao invalida no inventario")

        try:
            address = int(vram, 0)
        except (TypeError, ValueError) as exc:
            raise ProgressError(f"vram invalido no inventario: {name}") from exc

        if name in seen or not isinstance(size, int) or size <= 0 or address < 0:
            raise ProgressError(f"funcao invalida no inventario: {name}")

        seen.add(name)

    return functions


def resolve_source(root: Path, value: object) -> Path | None:
    if not isinstance(value, str):
        return None

    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        return None

    root = root.resolve()
    path = (root / relative).resolve()

    try:
        path.relative_to(root)
    except ValueError:
        return None

    return path


def proof_matches(root: Path, function: dict[str, object], proof: object) -> bool:
    if not isinstance(proof, dict):
        return False

    source = resolve_source(root, proof.get("source"))
    if source is None or not source.is_file():
        return False

    expected = {
        "format": FORMAT_VERSION,
        "target": TARGET,
        "function": function["name"],
        "vram": function["vram"],
        "size": function["size"],
    }

    if any(proof.get(key) != value for key, value in expected.items()):
        return False

    original_hash = proof.get("original_text_sha256")
    compiled_hash = proof.get("compiled_text_sha256")

    if (
        not isinstance(original_hash, str)
        or len(original_hash) != 64
        or original_hash != compiled_hash
    ):
        return False

    try:
        return proof.get("source_sha256") == sha256_file(source)
    except ProgressError:
        return False


def verified_matches(root: Path, functions: list[dict[str, object]]) -> set[str]:
    matched: set[str] = set()

    for function in functions:
        name = str(function["name"])
        proof_path = root / PROOFS_PATH / f"{name}.json"

        if not proof_path.is_file():
            continue

        try:
            proof = read_json(proof_path)
        except ProgressError:
            continue

        if proof_matches(root, function, proof):
            matched.add(name)

    return matched


def percentage(numerator: int, denominator: int) -> float:
    return round(numerator / denominator * 100, 6) if denominator else 0.0


def format_percentage(value: float) -> str:
    return f"{value:.2f}%" if value == 0.0 or value >= 0.01 else f"{value:.6f}%"


def format_count(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def badge_svg(label: str, value: str, color: str) -> bytes:
    label_width = max(52, len(label) * 7 + 14)
    value_width = max(62, len(value) * 7 + 14)
    width = label_width + value_width
    label_x = label_width / 2
    value_x = label_width + value_width / 2
    title = html.escape(f"{label}: {value}", quote=True)
    safe_label = html.escape(label)
    safe_value = html.escape(value)

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{title}">
  <title>{title}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#fff" stop-opacity=".7"/>
    <stop offset=".1" stop-color="#aaa" stop-opacity=".1"/>
    <stop offset=".9" stop-color="#000" stop-opacity=".3"/>
    <stop offset="1" stop-color="#000" stop-opacity=".5"/>
  </linearGradient>
  <clipPath id="r"><rect width="{width}" height="20" rx="3"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_x:g}" y="15" fill="#010101" fill-opacity=".3">{safe_label}</text>
    <text x="{label_x:g}" y="14">{safe_label}</text>
    <text x="{value_x:g}" y="15" fill="#010101" fill-opacity=".3">{safe_value}</text>
    <text x="{value_x:g}" y="14">{safe_value}</text>
  </g>
</svg>
"""
    return svg.encode("utf-8")


def report_unit(function: dict[str, object], exact: bool) -> dict[str, object]:
    name = str(function["name"])
    size = int(function["size"])
    measures: dict[str, object] = {
        "total_code": str(size),
        "total_functions": 1,
        "total_units": 1,
    }
    section: dict[str, object] = {"name": ".text", "size": str(size), "metadata": {}}
    function_entry: dict[str, object] = {
        "name": name,
        "size": str(size),
        "metadata": {},
        "address": "0",
    }

    if exact:
        measures.update(
            {
                "fuzzy_match_percent": 100.0,
                "matched_code": str(size),
                "matched_code_percent": 100.0,
                "matched_functions": 1,
                "matched_functions_percent": 100.0,
            }
        )
        section["fuzzy_match_percent"] = 100.0
        function_entry["fuzzy_match_percent"] = 100.0

    return {
        "name": f"src/cod/{name}",
        "measures": measures,
        "sections": [section],
        "functions": [function_entry],
        "metadata": {},
    }


def progress_values(
    functions: list[dict[str, object]], matched: set[str]
) -> tuple[int, int, int, int, float, float]:
    total_code = sum(int(function["size"]) for function in functions)
    matched_code = sum(
        int(function["size"])
        for function in functions
        if function["name"] in matched
    )
    matched_count = len(matched)
    total_count = len(functions)
    code_percent = percentage(matched_code, total_code)
    function_percent = percentage(matched_count, total_count)
    return (
        matched_code,
        total_code,
        matched_count,
        total_count,
        code_percent,
        function_percent,
    )


def report_document(
    functions: list[dict[str, object]], matched: set[str]
) -> dict[str, object]:
    matched_code, total_code, matched_count, total_count, code_percent, function_percent = (
        progress_values(functions, matched)
    )

    return {
        "measures": {
            "fuzzy_match_percent": code_percent,
            "total_code": str(total_code),
            "matched_code": str(matched_code),
            "matched_code_percent": code_percent,
            "total_functions": total_count,
            "matched_functions": matched_count,
            "matched_functions_percent": function_percent,
            "total_units": total_count,
        },
        "units": [
            report_unit(function, str(function["name"]) in matched)
            for function in functions
        ],
    }


def progress_outputs(
    functions: list[dict[str, object]], matched: set[str]
) -> tuple[dict[Path, bytes], int, int, float]:
    report = report_document(functions, matched)
    _, _, matched_count, total_count, code_percent, _ = progress_values(
        functions, matched
    )
    outputs = {
        REPORT_PATH: json_bytes(report),
        CODE_BADGE_PATH: badge_svg("Code", format_percentage(code_percent), "#007ec6"),
        FUNCTIONS_BADGE_PATH: badge_svg(
            "Functions",
            f"{format_count(matched_count)} / {format_count(total_count)}",
            "#4c1",
        ),
    }
    return outputs, matched_count, total_count, code_percent


def check_outputs(root: Path, outputs: dict[Path, bytes]) -> None:
    outdated = []

    for relative_path, expected in outputs.items():
        try:
            current = (root / relative_path).read_bytes()
        except OSError:
            outdated.append(relative_path.as_posix())
            continue

        if current != expected:
            outdated.append(relative_path.as_posix())

    if outdated:
        raise ProgressError(f"progresso desatualizado ({', '.join(outdated)})")


def generate_report(
    root: Path, *, check: bool = False, write: bool = True
) -> tuple[int, int, float]:
    functions = load_inventory(root)
    matched = verified_matches(root, functions)
    outputs, matched_count, total_count, code_percent = progress_outputs(
        functions, matched
    )

    if check:
        check_outputs(root, outputs)
    elif write:
        for relative_path, data in outputs.items():
            write_if_changed(root / relative_path, data)

    return matched_count, total_count, code_percent


def record_match(
    root: Path,
    *,
    name: str,
    source: Path,
    profile: str,
    vram: int,
    original: bytes,
    compiled: bytes,
) -> None:
    if original != compiled:
        raise ProgressError(f"nao e possivel registrar match inexato: {name}")

    functions = load_inventory(root)
    function = next(
        (function for function in functions if function["name"] == name), None
    )

    if function is None:
        raise ProgressError(f"{name} nao esta no inventario de funcoes")

    if int(str(function["vram"]), 0) != vram:
        raise ProgressError(f"vram de {name} diverge do inventario")

    if int(function["size"]) != len(original):
        raise ProgressError(f"tamanho de {name} diverge do inventario")

    root_resolved = root.resolve()
    source_resolved = source.resolve()

    try:
        relative_source = source_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ProgressError("fonte fora do projeto") from exc

    text_hash = sha256_bytes(original)
    proof = {
        "format": FORMAT_VERSION,
        "target": TARGET,
        "function": name,
        "vram": function["vram"],
        "size": function["size"],
        "profile": profile,
        "source": relative_source.as_posix(),
        "source_sha256": sha256_file(source_resolved),
        "original_text_sha256": text_hash,
        "compiled_text_sha256": sha256_bytes(compiled),
    }
    write_if_changed(root / PROOFS_PATH / f"{name}.json", json_bytes(proof))


def invalidate_match(root: Path, name: str) -> None:
    try:
        (root / PROOFS_PATH / f"{name}.json").unlink(missing_ok=True)
    except OSError as exc:
        raise ProgressError(f"erro ao invalidar o progresso de {name}: {exc}") from exc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="gera o relatorio e os badges locais de progresso"
    )
    parser.add_argument(
        "--update-inventory",
        action="store_true",
        help="rele os arquivos asm e atualiza a lista total de funcoes",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="falha se o relatorio versionado estiver desatualizado",
    )
    mode.add_argument(
        "--summary",
        action="store_true",
        help="calcula o progresso sem alterar os arquivos agregados",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(__file__).resolve().parents[1]

    try:
        if args.update_inventory:
            functions = update_inventory(root)
            print(f"inventario: {len(functions)} funcoes")

        matched, total, code_percent = generate_report(
            root, check=args.check, write=not args.summary
        )
    except ProgressError as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.check:
        status = "validado"
    elif args.summary:
        status = "calculado"
    else:
        status = "atualizado"

    print(
        f"progresso {status}: {matched}/{total} funcoes; "
        f"{code_percent:.6f}% do codigo"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
