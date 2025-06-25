'''
    This is a python script used to automatically analyze multiple binaries 
    inside a folder. It also automatically decompresses archive .a files
    and analyzes those files as well. This was created as a workaround for
    the lack of headless/GUI-less processing to automatically analyze 
    multiple binaries and measure the performance of the plugin
    To use, just paste the code in the Binary Ninja python console and
    update the necessary paths at the end of the script.
'''

# ------------------------------------------------------------
#  Time-and-count analyser for Xtensa objects / archives
# ------------------------------------------------------------
import pathlib, subprocess, tempfile, shutil, time, csv, collections, binaryninja as bn
from binaryninja.lowlevelil import LowLevelILOperation as LLO
_UNIMPL_OPS = {LLO.LLIL_UNIMPL, LLO.LLIL_UNIMPL_MEM}
# ---------- helpers ----------------------------------------------------

def _mnemonic_at(bv: "bn.BinaryView", addr: int) -> str:
    try:
        tokens, _ = bv.get_instruction_text(addr)
        for tok in tokens:
            if tok.type.name == "InstructionToken":
                return tok.text.upper()
    except Exception:
        pass
    try:
        return bv.get_disassembly(addr).split()[0].upper()
    except Exception:
        return "UNKNOWN"

def ensure_xtensa(bv: "bn.BinaryView", arch):
    if bv.arch.name.lower() != arch:
        try:
            xtensa = bn.Architecture[arch]
            bv.platform = xtensa.standalone_platform
        except KeyError:
            raise f"ERROR, {arch} not supported"
            pass

def analyse_object(path: pathlib.Path, csv_writer, arch):
    """Analyse *path* and append one detailed CSV row."""
    size_bytes = path.stat().st_size
    bv = bn.load(str(path), update_analysis=False, options={'loader.platform' : arch} )
    ensure_xtensa(bv, arch)
    t0 = time.perf_counter()
    bv.update_analysis_and_wait()          # wait for full IL
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    time.sleep(0.2)
    # freeze the function list to avoid NoneType races
    functions = [f for f in bv.functions
                 if f is not None and f.low_level_il is not None]
    fn_cnt  = len(functions)
    ins_cnt = sum(1 for fn in functions for _ in fn.instructions)
    mnem_counter = collections.Counter()
    unimpl_cnt   = 0
    for fn in functions:
        if fn.low_level_il == None:
            continue
        for il in fn.low_level_il.instructions:
            if il.operation in _UNIMPL_OPS:
                unimpl_cnt += 1
                mnem_counter[_mnemonic_at(bv, il.address)] += 1
    # -------- CSV ROW (adds all requested metrics) --------------------
    csv_writer.writerow([
        path.name,                 # file
        size_bytes,                # size_bytes
        f"{elapsed_ms:.3f}",       # elapsed_ms
        fn_cnt,                    # functions
        ins_cnt,                   # instructions
        unimpl_cnt                 # unimpl_total
    ])
    # -----------------------------------------------------------------
    bv.file.close()
    return fn_cnt, ins_cnt, unimpl_cnt, mnem_counter, elapsed_ms, size_bytes
# ---------- main driver (unchanged apart from header) -----------------

def count_in_folder(folder: str | pathlib.Path, csv_path: str | pathlib.Path, arch:str):
    
    print(f"##################")
    print(f"RESULTS FOR {arch}")
    print(f"##################")
    start = time.perf_counter()
    folder, csv_path = map(pathlib.Path, (folder, csv_path))
    if not folder.is_dir():
        print(f"ERROR: {folder} is not a directory"); return
    if not shutil.which("ar"):
        print("ERROR: `ar` (binutils) not found in PATH"); return
    need_header = not csv_path.exists()
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    csv_file   = csv_path.open("a", newline="")
    csv_writer = csv.writer(csv_file)
    if need_header:
        csv_writer.writerow(
            ["file", "size_bytes", "elapsed_ms",
             "functions", "instructions", "unimpl_total"]
        )
    grand_fn = grand_ins = grand_un = total_files = 0
    grand_mnems = collections.Counter()
    # -- stand-alone .o / .elf ----------------------------------------
    standalone = sorted(folder.glob("*.o")) + sorted(folder.glob("*.elf"))
    if standalone:
        print("\n📄 Stand-alone object / ELF files")
    for obj in standalone:
        try:
            fn, ins, unimpl, mnems, t_ms, _ = analyse_object(obj, csv_writer, arch)
            print(f"  {obj.name:25} {fn:3} fn {ins:6} ins "
                  f"{unimpl:3} unimpl {t_ms:7.1f} ms")
            grand_fn += fn; grand_ins += ins; grand_un += unimpl
            grand_mnems += mnems; total_files += 1
        except Exception as e:
            standalone.append(obj) # If there was an error, try again
            print(f"  {obj.name}: error — {e}")
    # -- each .a archive ---------------------------------------------
    for archive in sorted(folder.glob("*.a")):
        print(f"\n📚 {archive.name}")
        arc_fn = arc_ins = arc_un = 0
        arc_mnems = collections.Counter()
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            members = subprocess.check_output(
                ["ar", "t", archive], text=True).splitlines()
            for member in members: 
                obj = tmp / member
                obj.parent.mkdir(parents=True, exist_ok=True)
                with open(obj, "wb") as out:
                    subprocess.check_call(["ar", "p", archive, member], stdout=out)
                try:
                    fn, ins, unimpl, mnems, t_ms, _ = analyse_object(obj, csv_writer, arch)
                    print(f"  {member:25} {fn:3} fn {ins:6} ins "
                          f"{unimpl:3} unimpl {t_ms:7.1f} ms")
                    arc_fn += fn; arc_ins += ins; arc_un += unimpl
                    arc_mnems += mnems; total_files += 1
                except Exception as e:
                    members.append(member) # If there was an error, try again
                    print(f"  {member}: error — {e}")
        print(f"  ↪ subtotal: {arc_fn} fn, {arc_ins} ins, {arc_un} unimpl")
        for m, c in arc_mnems.most_common():
            print(f"     • {m:<10} {c}")
        grand_fn += arc_fn; grand_ins += arc_ins; grand_un += arc_un
        grand_mnems += arc_mnems
    # -- grand summary -----------------------------------------------
    print("\n=== GRAND TOTALS ===")
    print(f"Files evaluated:             {total_files}")
    print(f"Functions decompiled:        {grand_fn}")
    print(f"Disassembled instructions:   {grand_ins}")
    print(f"'unimplemented' instructions:{grand_un}\n")
    total_time = (time.perf_counter() - start) * 1000.0
    print(f"Run Time of all test cases   :{total_time}\n")
    print("Break-down of unimplemented mnemonics:")
    for m, c in grand_mnems.most_common():
        print(f"  {m:<10} {c}")
    csv_file.close()
    print(f"\nCSV results appended → {csv_path}")

# ------------------ EDIT THESE TWO LINES THEN RUN --------------------------
TARGET_DIR  = "path/to/target/folder/with/binaries"

RESULTS_CSV = "path/to/file/to/store/results/into" # Will be created or appended to
# ---------------------------------------------------------------------------
count_in_folder(TARGET_DIR, RESULTS_CSV, "xtensa")
