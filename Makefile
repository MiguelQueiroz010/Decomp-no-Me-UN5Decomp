PYTHON ?= python3
PROFILE ?= mwcc24_o3p
SRC_DIR ?= src/cod
ELF_OUTPUT ?= build/SLES_556.05.elf
JOBS ?= 8

.PHONY: setup tools match elf clean

setup:
	@$(PYTHON) tools/setup.py --verbose

tools:
	@$(PYTHON) tools/setup_tools.py

match:
	@test -n "$(FUNC)" || (echo "use: make match FUNC=func_XXXXXXXX" >&2; exit 2)
	@test "$(PROFILE)" = "mwcc24_o3p" || (echo "objdiff.json usa o perfil mwcc24_o3p" >&2; exit 2)
	@$(PYTHON) tools/match.py src/cod/$(FUNC).c $(PROFILE) --objdiff

elf:
	@$(PYTHON) tools/build_elf.py \
		--profile $(PROFILE) \
		--source-dir $(SRC_DIR) \
		--output $(ELF_OUTPUT) \
		--jobs $(JOBS) \
		$(if $(filter 1,$(STRICT)),--require-match,)

clean:
	@rm -rf asm assets build
	@rm -f baserom/SLES_556.05.rom
	@rm -f config/SLES_556.05.ld
	@rm -rf config/auto
	@mkdir -p asm/cod assets/cod build config/auto
	@touch asm/cod/.gitkeep
	@touch assets/cod/.gitkeep
	@touch build/.gitkeep
	@touch config/auto/.gitkeep
