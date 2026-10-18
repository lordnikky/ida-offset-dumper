import builtins
import os
import re

import idautils
import ida_funcs
import ida_nalt
import ida_bytes
import ida_ua
import ida_hexrays
import idc

BASE = ida_nalt.get_imagebase()
MAX_EA = 0x10000000000
PUSHFSTRING = None
RUNERROR = None

_builtin_print = builtins.print
_LINES = []


def print(*args, **kwargs):
    text = " ".join(str(a) for a in args)
    _LINES.append(text)
    _builtin_print(text, **kwargs)


def _is_func_start(q):
    if q >= MAX_EA:
        return False
    try:
        f = ida_funcs.get_func(q)
    except Exception:
        return False
    return f is not None and f.start_ea == q


def _pair_name(ea):
    if ea >= MAX_EA:
        return None
    try:
        s = idc.get_strlit_contents(ea)
    except Exception:
        return None
    if isinstance(s, bytes):
        try:
            s = s.decode()
        except UnicodeDecodeError:
            return None
    if s and len(s) < 64 and all(32 <= ord(c) < 127 for c in s):
        return s
    return None


def _pair_valid(ea):
    try:
        name = ida_bytes.get_qword(ea)
        func = ida_bytes.get_qword(ea + 8)
    except Exception:
        return None
    if not _is_func_start(func):
        return None
    s = _pair_name(name)
    return (s, func) if s else None


_SCAN_CACHE = {}
_SCAN_SEGS = (".rdata", ".data")


def _seg_blob(name):
    key = "blob:" + name
    if key in _SCAN_CACHE:
        return _SCAN_CACHE[key]
    blob = None
    try:
        import ida_segment
        seg = ida_segment.get_segm_by_name(name)
        if seg is not None:
            start = int(seg.start_ea)
            size = int(seg.end_ea) - start
            if 0 < size <= 0x8000000:
                data = ida_bytes.get_bytes(start, size)
                if data:
                    blob = (start, data)
    except Exception:
        blob = None
    _SCAN_CACHE[key] = blob
    return blob


def _scan_bytes(pattern, exact=False):
    key = (pattern, exact)
    if key in _SCAN_CACHE:
        return _SCAN_CACHE[key]
    res = None
    try:
        needle = pattern + ("\x00" if exact else "")
        needle = needle.encode("latin-1")
    except Exception:
        needle = b""
    head = pattern[:1]
    check_prev = exact and (head.isalnum() or head == "_")
    if needle:
        for segname in _SCAN_SEGS:
            blob = _seg_blob(segname)
            if blob is None:
                continue
            start, data = blob
            pos = data.find(needle)
            while pos >= 0:
                ok = True
                if check_prev and pos > 0:
                    prev = data[pos - 1]
                    if (prev == 0x5F or 0x30 <= prev <= 0x39
                            or 0x41 <= prev <= 0x5A or 0x61 <= prev <= 0x7A):
                        ok = False
                if ok:
                    if exact:
                        res = start + pos
                        break
                    s0 = pos
                    while s0 > 0 and data[s0 - 1] != 0 and pos - s0 < 512:
                        s0 -= 1
                    if all(0x20 <= b < 0x7F for b in data[s0:pos]):
                        res = start + s0
                        break
                pos = data.find(needle, pos + 1)
            if res is not None:
                break
    _SCAN_CACHE[key] = res
    return res


def find_str(pattern, exact=False):
    import ida_strlist
    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    for i in range(qty):
        if not ida_strlist.get_strlist_item(si, i):
            continue
        raw = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
        if not raw:
            continue
        try:
            t = raw.decode()
        except UnicodeDecodeError:
            continue
        if (t == pattern) if exact else (pattern in t):
            return si.ea
    return _scan_bytes(pattern, exact)


def func_of(ea):
    if ea is None:
        return None
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None


def dump_func(name, pattern, n=1, exact=False):
    s = find_str(pattern, exact)
    if not s:
        print("%s: NO STRING" % name)
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if len(xs) < n:
        print("%s: only %d xrefs" % (name, len(xs)))
        return None
    f = func_of(xs[n - 1])
    if f is None:
        print("%s: xref 0x%x not in func" % (name, xs[n - 1]))
        return None
    print("%s = REBASE(0x%X)" % (name, f - BASE))
    return f


def dump_symbol(name, symbol):
    for ea, nm in idautils.Names():
        if nm == symbol:
            print("%s = REBASE(0x%X)" % (name, ea - BASE))
            return ea
    print("%s: NO SYMBOL" % name)
    return None


def dump_slot_before(name, symbol, delta):
    for ea, nm in idautils.Names():
        if nm == symbol:
            addr = ea - delta
            f = func_of(int(ida_bytes.get_qword(addr)))
            if f is None:
                print("%s: slot 0x%X not in func" % (name, addr))
                return None
            print("%s = REBASE(0x%X)" % (name, f - BASE))
            return f
    print("%s: NO SYMBOL" % name)
    return None


def _is_offset_xref(x):
    try:
        import ida_xref
    except Exception:
        return False
    try:
        return x.type == ida_xref.dr_O
    except Exception:
        return False


def dump_offset_xref_func(name, pattern, n=1):
    s = find_str(pattern, exact=True)
    if s is None:
        s = find_str(pattern)
    if s is None:
        print("%s: NO STRING" % name)
        return None
    offs = []
    refs = []
    data = []
    for x in idautils.XrefsTo(s):
        f = func_of(x.frm)
        if f is None:
            continue
        if x.iscode:
            (offs if _is_offset_xref(x) else refs).append(f)
        else:
            data.append(f)
    pick = offs or refs or data
    pick.sort()
    if len(pick) < n:
        print("%s: NO XREF" % name)
        return None
    f = pick[n - 1]
    print("%s = REBASE(0x%X)" % (name, f - BASE))
    return f


def dump_func_any(name, patterns):
    votes = {}
    order = []
    for p in patterns:
        s = find_str(p, exact=True)
        if s is None:
            s = find_str(p)
        if s is None:
            continue
        refs = {}
        for x in idautils.XrefsTo(s):
            f = func_of(x.frm)
            if f is None:
                continue
            if f not in refs or x.frm < refs[f]:
                refs[f] = x.frm
        for f in sorted(refs, key=lambda k: refs[k]):
            if f not in votes:
                votes[f] = 0
                order.append(f)
            votes[f] += 1
    if not order:
        print("%s: NO STRING" % name)
        return None
    best = max(order, key=lambda k: votes[k])
    print("%s = REBASE(0x%X)" % (name, best - BASE))
    return best


def _insns(fstart):
    if fstart is None:
        return []
    f = ida_funcs.get_func(fstart)
    out = []
    if f is None:
        return out
    for ea in idautils.Heads(f.start_ea, f.end_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea):
            out.append((ea, insn))
    return out


def scan_calls(fstart):
    out = []
    for ea, insn in _insns(fstart):
        if insn.get_canon_mnem() != "call":
            continue
        for i in range(6):
            op = insn[i]
            if op.type == ida_ua.o_near:
                out.append((ea, op.addr))
                break
    return out


def first_call_in(fstart):
    c = scan_calls(fstart)
    return c[0][1] if c else None


def _as_func(ea):
    if ea is None:
        return None
    return func_of(ea) or ea


def _vtable_slot(vt, idx):
    if vt is None:
        return None
    try:
        ea = int(ida_bytes.get_qword(vt + idx * 8))
    except Exception:
        return None
    return func_of(ea)


def _call_in_region(pattern, region):
    if region is None:
        return None
    s = find_str(pattern, exact=True)
    if s is None:
        s = find_str(pattern)
    if s is None:
        return None
    lo = region & 0xFFFFFFFFFFFF0000
    hi = lo + 0x10000
    for x in idautils.XrefsTo(s):
        f = func_of(x.frm)
        if f is None:
            continue
        for _, tgt in scan_calls(f):
            if lo <= tgt < hi:
                return tgt
    return None


def _seg_name(ea):
    try:
        import ida_segment
        seg = ida_segment.getseg(ea)
        if seg is None:
            return None
        return ida_segment.get_segm_name(seg)
    except Exception:
        return None


def dump_flag_global(name, pattern):
    s = find_str(pattern, exact=True)
    if s is None:
        s = find_str(pattern)
    if s is None:
        print("%s: NO STRING" % name)
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        print("%s: NO XREF" % name)
        return None
    f = func_of(xs[0])
    if f is None:
        print("%s: xref not in func" % name)
        return None
    lst = _insns(f)
    idx = next((i for i, (a, _) in enumerate(lst) if a == xs[0]), None)
    if idx is None:
        print("%s: NO STRING REF" % name)
        return None
    for k in range(max(0, idx - 8), min(len(lst), idx + 16)):
        ni = lst[k][1]
        for t in range(6):
            op = ni[t]
            if op.type != ida_ua.o_mem or op.addr == s or op.addr >= MAX_EA:
                continue
            if _seg_name(op.addr) == ".text":
                continue
            print("%s = REBASE(0x%X)" % (name, op.addr - BASE))
            return op.addr
    print("%s: NO GLOBAL" % name)
    return None


def dump_flag_ptr(name, pattern, n=1):
    s = find_str(pattern, exact=True)
    if s is None:
        s = find_str(pattern)
    if s is None:
        print("%s: NO STRING" % name)
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        print("%s: NO XREF" % name)
        return None
    order = (xs[n - 1:] + xs[:n - 1]) if len(xs) >= n else xs
    for ref in order:
        f = func_of(ref)
        if f is None:
            continue
        fn = ida_funcs.get_func(f)
        if fn is None or (fn.end_ea - fn.start_ea) > 0x100:
            continue
        hits = []
        for _, ni in _insns(f):
            if ni.get_canon_mnem() != "lea":
                continue
            oo = _ops(ni)
            if (len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[0].reg == 8
                    and oo[1].type == ida_ua.o_mem and oo[1].addr != s
                    and _seg_name(oo[1].addr) != ".text"):
                hits.append(oo[1].addr)
        if len(hits) == 1:
            print("%s = REBASE(0x%X)" % (name, hits[0] - BASE))
            return hits[0]
    print("%s: NO GLOBAL" % name)
    return None


_REG_ALIASES = {
    0: "rax", 1: "rcx", 2: "rdx", 3: "rbx", 4: "rsp", 5: "rbp", 6: "rsi", 7: "rdi",
    8: "r8", 9: "r9", 10: "r10", 11: "r11", 12: "r12", 13: "r13", 14: "r14", 15: "r15",
}


def _reg_name(reg):
    try:
        n = idc.get_reg_name(reg)
        if n:
            return n.lower()
    except Exception:
        pass
    try:
        import ida_idp
        n = ida_idp.get_reg_name(reg)
        if n:
            return n.lower()
    except Exception:
        pass
    return _REG_ALIASES.get(reg)


def _call_arg_lea_byte(call_ea, regs, byteval, fstart):
    lst = _insns(fstart)
    idx = next((i for i, (a, _) in enumerate(lst) if a == call_ea), None)
    if idx is None:
        return False
    for i in range(idx - 1, max(-1, idx - 16), -1):
        ni = lst[i][1]
        if ni.get_canon_mnem() != "lea":
            continue
        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
        if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_mem:
            if _reg_name(oo[0].reg) in regs:
                return ida_bytes.get_byte(oo[1].addr) == byteval
    return False


def _call_arg_imm(call_ea, regs, val, fstart):
    lst = _insns(fstart)
    idx = next((i for i, (a, _) in enumerate(lst) if a == call_ea), None)
    if idx is None:
        return False
    for i in range(idx - 1, max(-1, idx - 16), -1):
        ni = lst[i][1]
        if ni.get_canon_mnem() != "mov":
            continue
        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
        if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_imm:
            if _reg_name(oo[0].reg) in regs and (oo[1].value & 0xFFFFFFFF) == val:
                return True
    return False


def dump_streams():
    s = find_str("RtcAppConnection::close", exact=True)
    f = None
    if s is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(s))
        if xs:
            f = func_of(xs[0])
    if f is None:
        print("StreamCreate: NO STRING")
        print("StreamAppend: NO STRING")
        print("StreamDestroy: NO STRING")
        return
    calls = scan_calls(f)
    create = None
    append = None
    for ea, tgt in calls:
        if append is None and _call_arg_lea_byte(ea, ("edx", "rdx", "dx"), 0x08, f):
            append = tgt
    for ea, tgt in calls:
        if _call_arg_imm(ea, ("edx", "rdx", "dx"), 10, f) and _call_arg_imm(ea, ("r8d", "r8"), 8, f):
            create = tgt
            break
    if create is None:
        for ea, tgt in calls:
            if _call_arg_imm(ea, ("edx", "rdx", "dx"), 10, f):
                create = tgt
                break
    destroy = calls[0][1] if calls else None
    if destroy is not None and (destroy == create or destroy == append):
        destroy = next((t for _, t in calls if t != create and t != append), None)
    print("StreamCreate = REBASE(0x%X)" % (_as_func(create) - BASE) if create is not None else "StreamCreate: NO CALL")
    print("StreamAppend = REBASE(0x%X)" % (_as_func(append) - BASE) if append is not None else "StreamAppend: NO CALL")
    print("StreamDestroy = REBASE(0x%X)" % (_as_func(destroy) - BASE) if destroy is not None else "StreamDestroy: NO CALL")


def dump_caller(name, target):
    callers = sorted(x.frm for x in idautils.XrefsTo(target) if x.iscode)
    if not callers:
        print("%s: NO CALLERS" % name)
        return None
    f = func_of(callers[0])
    if f is None:
        print("%s: caller 0x%x not in func" % (name, callers[0]))
        return None
    print("%s = REBASE(0x%X)" % (name, f - BASE))
    return f


def find_vtable(mangled):
    for ea, name in idautils.Names():
        if name == mangled:
            ok = 0
            for i in range(6):
                e = int(ida_bytes.get_qword(ea + i * 8))
                if ida_funcs.get_func(e):
                    ok += 1
            if ok >= 4:
                return ea
            print("%s @ 0x%X failed validation" % (mangled, ea))
            return None
    print("%s: NO SYMBOL" % mangled)
    return None


def _rtti_locator(td_ea):
    rva = td_ea - BASE
    if rva <= 0:
        return None
    blob = _seg_blob(".rdata")
    if blob is None:
        return None
    start, data = blob
    needle = rva.to_bytes(4, "little")
    pos = data.find(needle)
    while pos >= 0:
        if pos % 4 == 0 and pos >= 12:
            col = start + pos - 12
            try:
                sig = int(ida_bytes.get_dword(col))
                self_rva = int(ida_bytes.get_dword(col + 20))
            except Exception:
                sig = self_rva = None
            if sig == 1 and self_rva == col - BASE:
                return col
        pos = data.find(needle, pos + 1)
    return None


def _rtti_vtable(mangled_td):
    td = find_str(mangled_td, exact=True)
    if td is None:
        for ea, nm in idautils.Names():
            if nm == mangled_td:
                td = ea
                break
    if td is None:
        return None
    col = _rtti_locator(td)
    if col is None:
        return None
    blob = _seg_blob(".rdata")
    if blob is None:
        return None
    start, data = blob
    needle = col.to_bytes(8, "little")
    pos = data.find(needle)
    while pos >= 0:
        if pos % 8 == 0:
            vt = start + pos + 8
            try:
                s0 = int(ida_bytes.get_qword(vt))
            except Exception:
                s0 = None
            if s0 is not None and _is_func_start(s0):
                return vt
        pos = data.find(needle, pos + 1)
    return None


_VFTABLES = (
    ("vftNetworkStream", ".?AVNetworkStream@Network@RBX@@", "??_7NetworkStream@Network@RBX@@6B@"),
    ("vftMessageScriptSlot", ".?AVMessageSlotImpl@Lua@RBX@@", "??_7MessageSlotImpl@Lua@RBX@@6B@"),
    ("vftWaitScriptSlot", ".?AVWaitScriptSlot@Lua@RBX@@", "??_7WaitScriptSlot@Lua@RBX@@6B@"),
    ("vftFuncScriptSlot0", ".?AV?$FunctionScriptSlotImpl@$00@Lua@RBX@@",
     "??_7?$FunctionScriptSlotImpl@$00@Lua@RBX@@6B@"),
    ("vftFuncScriptSlot1", ".?AV?$FunctionScriptSlotImpl@$0A@@Lua@RBX@@",
     "??_7?$FunctionScriptSlotImpl@$0A@@Lua@RBX@@6B@"),
)


def dump_rtti_vtables():
    print("--- vftables ---")
    for out, td, sym in _VFTABLES:
        vt = find_vtable(sym)
        if vt is None:
            vt = _rtti_vtable(td)
        if vt is None:
            print("%s: NO VTABLE" % out)
            continue
        print("%s = REBASE(0x%X)" % (out, vt - BASE))


def dump_tasks():
    print("--- task ---")
    dump_func("TaskDefer", "task.defer is not available for AuroraScripts")
    dump_func("TaskSpawn", "task.spawn is not available for AuroraScripts")
    dump_func("TaskDelay", "task.delay is not available for AuroraScripts")
    dump_func("TaskWait", "task.wait is not available for AuroraScripts")
    dump_func("TaskDesynchronize", "task.desynchronize() may only be called")
    dump_func("TaskCancel", "Cannot call task.")
    dump_func("TaskSynchronize", "task.synchronize() may only be called")


_FIREMOUSE_PATS = [
    "DragDetector::updateMouseState LeftMouseUp",
    "DragDetector::updateMouseState",
    "DragDetector",
    "updateMouseState",
    "LeftMouseUp",
]


def _firemouse_scan(fstart):
    lst = _insns(fstart)
    fire = None
    right = None
    for i, (a, ni) in enumerate(lst):
        if ni.get_canon_mnem() != "call":
            continue
        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
        if not oo or oo[0].type != ida_ua.o_near:
            continue
        has312 = False
        has313 = False
        for k in range(max(0, i - 12), i):
            m2 = lst[k][1].get_canon_mnem()
            o2 = [lst[k][1][t] for t in range(6) if lst[k][1][t].type != ida_ua.o_void]
            if m2 in ("test", "cmp"):
                for o in o2:
                    if o.type == ida_ua.o_displ and o.addr == 312:
                        has312 = True
                    if o.type == ida_ua.o_displ and o.addr == 313:
                        has313 = True
            elif m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[1].type == ida_ua.o_displ:
                if o2[1].addr == 312:
                    has312 = True
                if o2[1].addr == 313:
                    has313 = True
        if has312 and fire is None:
            for k in range(i + 1, min(len(lst), i + 8)):
                m2 = lst[k][1].get_canon_mnem()
                o2 = [lst[k][1][t] for t in range(6) if lst[k][1][t].type != ida_ua.o_void]
                if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_displ and o2[0].addr == 312:
                    fire = oo[0].addr
                    break
        if has313 and right is None:
            right = oo[0].addr
        if fire is not None and right is not None:
            break
    return (fire, right)


def dump_firemouse():
    import ida_strlist
    found = {}
    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    for i in range(qty):
        if not ida_strlist.get_strlist_item(si, i):
            continue
        raw = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
        if not raw:
            continue
        try:
            t = raw.decode()
        except UnicodeDecodeError:
            continue
        for p in _FIREMOUSE_PATS:
            if p not in found and p in t:
                found[p] = si.ea
        if len(found) >= len(_FIREMOUSE_PATS):
            break
    funcs = []
    seen = set()
    for p in _FIREMOUSE_PATS:
        if p not in found:
            continue
        for x in sorted(x.frm for x in idautils.XrefsTo(found[p])):
            f = func_of(x)
            if f is None or f in seen:
                continue
            seen.add(f)
            funcs.append(f)
            if len(funcs) >= 24:
                break
        if len(funcs) >= 24:
            break
    if not funcs:
        if not found:
            print("FireMouseClick: NO STRING")
            print("FireRightMouseClick: NO STRING")
        else:
            print("FireMouseClick: NO XREF")
            print("FireRightMouseClick: NO XREF")
        return
    partial = None
    for f in funcs:
        fire, right = _firemouse_scan(f)
        if fire is not None and right is not None:
            print("FireMouseClick = REBASE(0x%X)" % (fire - BASE))
            print("FireRightMouseClick = REBASE(0x%X)" % (right - BASE))
            return
        if partial is None and (fire is not None or right is not None):
            partial = (fire, right)
    if partial is not None:
        fire, right = partial
        if fire is not None:
            print("FireMouseClick = REBASE(0x%X)" % (fire - BASE))
        else:
            print("FireMouseClick: NO CALL")
        if right is not None:
            print("FireRightMouseClick = REBASE(0x%X)" % (right - BASE))
        else:
            print("FireRightMouseClick: NO CALL")
    else:
        print("FireMouseClick: NO CALL")
        print("FireRightMouseClick: NO CALL")


def dump_instance():
    print("--- instance ---")
    dump_func("InstanceNew", "Unable to create an Instance of type")
    dump_func("InstanceFindFirstAncestor", "FindFirstAncestorWhichIsA")
    dump_func("InstanceGetAttribute", "Part {} is too large, treating as persistent")
    dump_func("InstanceFindFirstChild", "FindFirstChild", exact=True)
    dump_func("InstanceFindFirstChildOfClass", "FindFirstChildOfClass")
    dump_func("InstanceGetChildren", "GetChildren", exact=True)
    dump_func("InstanceIndex", "InstanceHandle is not enabled yet!")
    dump_func("FireTouchInterest", "assembly primitive is null")
    dump_func("FireProximityPrompt", "ProximityPrompt_Triggered")
    dump_firemouse()


def dump_table(anchor, title, fmt):
    print("--- %s ---" % title)
    s = find_str(anchor, exact=True)
    if not s:
        print("%s: NO STRING" % title)
        return
    refs = sorted(x.frm for x in idautils.XrefsTo(s) if not x.iscode)
    if not refs:
        print("%s: NO TABLE REF" % title)
        return
    seen = set()
    for ref in refs:
        base = ref
        while True:
            prev = _pair_valid(base - 16)
            if prev is None:
                break
            base -= 16
        ea = base
        count = 0
        while count < 40:
            p = _pair_valid(ea)
            if p is None:
                break
            name, func = p
            key = (name, func)
            if key not in seen:
                seen.add(key)
                print(fmt % (name.capitalize(), func - BASE))
            ea += 16
            count += 1


def dump_coroutine():
    dump_table("isyieldable", "coroutine", "Coroutine%s = REBASE(0x%X)")


def dump_luab():
    dump_table("setmetatable", "luab", "LuaB%s = REBASE(0x%X)")


_GLOBAL_TABLE = (
    "print", "warn", "tick", "delay", "wait", "spawn", "loadstring", "require",
    "getfenv", "setfenv", "collectgarbage", "typeof", "newproxy", "unpack",
    "pcall", "xpcall", "select", "rawget", "rawset", "rawlen", "rawequal",
    "ipairs", "pairs", "next", "tonumber", "tostring", "error", "assert",
)

_GLOBAL_OUT = {
    "print": "Print",
    "warn": "Warn",
    "tick": "Tick",
    "delay": "Delay",
    "wait": "Wait",
    "spawn": "Spawn",
    "loadstring": "Loadstring",
    "require": "Require",
    "getfenv": "GetFenv",
    "setfenv": "SetFenv",
    "collectgarbage": "CollectGarbage",
}


def _table_base(ea):
    base = ea
    for _ in range(128):
        if _pair_valid(base - 16) is None:
            break
        base -= 16
    return base


def dump_global_table():
    print("--- global ---")
    cands = {}
    for nm in _GLOBAL_TABLE:
        s = find_str(nm, exact=True)
        if s is None:
            continue
        seen = 0
        for x in idautils.XrefsTo(s):
            if x.iscode:
                continue
            seen += 1
            if seen > 128:
                break
            if _pair_valid(x.frm) is None:
                continue
            b = _table_base(x.frm)
            cands[b] = cands.get(b, 0) + 1
    if not cands:
        print("GlobalTable: NO TABLE")
        return None
    base = max(cands, key=lambda k: cands[k])
    if cands[base] < 4:
        print("GlobalTable: WEAK n=%d" % cands[base])
        return None
    print("GlobalTable = REBASE(0x%X)" % (base - BASE))
    seen = set()
    ea = base
    for _ in range(128):
        p = _pair_valid(ea)
        if p is None:
            break
        name, func = p
        out = _GLOBAL_OUT.get(name) or name.capitalize()
        if out not in seen:
            seen.add(out)
            print("Global%s = REBASE(0x%X)" % (out, func - BASE))
        ea += 16
    return base


def _datasite_ok(call_ea):
    sa = call_ea - 1
    found = False
    for _ in range(60):
        if sa <= 0:
            break
        s2 = ida_ua.insn_t()
        if ida_ua.decode_insn(s2, sa):
            if s2.get_canon_mnem() == "lea":
                ops = [s2[j] for j in range(6) if s2[j].type != ida_ua.o_void]
                if len(ops) == 2 and ops[0].type == ida_ua.o_reg and ops[0].reg == 2 and ops[1].type == ida_ua.o_displ:
                    found = True
                    break
        sa -= 1
    if not found:
        return False
    f = ida_funcs.get_func(call_ea)
    end = f.end_ea if f else call_ea + 0x100
    insn = ida_ua.insn_t()
    sa = call_ea + (insn.size if ida_ua.decode_insn(insn, call_ea) else 1)
    for _ in range(15):
        if sa >= end:
            break
        s2 = ida_ua.insn_t()
        if not ida_ua.decode_insn(s2, sa):
            sa += 1
            continue
        for j in range(6):
            op = s2[j]
            if op.type == ida_ua.o_displ and op.addr == 0x30:
                return True
        sa += s2.size
    return False


def _calls_in(a, b):
    out = []
    ea = a
    while ea < b:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            ea += 1
            continue
        if insn.get_canon_mnem() == "call":
            for i in range(6):
                op = insn[i]
                if op.type == ida_ua.o_near:
                    out.append((ea, op.addr))
                    break
        ea += insn.size if insn.size else 1
    return out


def _data_range():
    import ida_segment
    seg = ida_segment.get_segm_by_name(".data")
    return (int(seg.start_ea), int(seg.end_ea))


def _str_eas():
    import ida_strlist
    out = set()
    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    for i in range(qty):
        if ida_strlist.get_strlist_item(si, i):
            out.add(si.ea)
    return out


def _func_refs_str(fstart, targets):
    f = ida_funcs.get_func(fstart)
    if not f:
        return False
    ea = f.start_ea
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            ea += 1
            continue
        for i in range(6):
            op = insn[i]
            if op.type == ida_ua.o_mem and op.phrase == 5 and op.addr in targets:
                return True
        ea += insn.size if insn.size else 1
    return False


def _has_calls(fstart):
    f = ida_funcs.get_func(fstart)
    if not f:
        return True
    ea = f.start_ea
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            ea += 1
            continue
        if insn.get_canon_mnem() == "call":
            return True
        ea += insn.size if insn.size else 1
    return False


def _vararg_prologue(fstart):
    f = ida_funcs.get_func(fstart)
    spill = set()
    n = 0
    for h in idautils.Heads(f.start_ea, f.end_ea):
        if n >= 8:
            break
        ni = ida_ua.insn_t()
        if not ida_ua.decode_insn(ni, h):
            continue
        n += 1
        if ni.get_canon_mnem() != "mov":
            continue
        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
        if len(oo) == 2 and oo[0].type == ida_ua.o_displ and oo[0].reg == 4 and oo[1].type == ida_ua.o_reg:
            spill.add((oo[0].addr, oo[1].reg))
    return (0x10, 2) in spill and (0x18, 8) in spill and (0x20, 9) in spill


def _retn_no_int3(fstart):
    f = ida_funcs.get_func(fstart)
    r = False
    for h in idautils.Heads(f.start_ea, f.end_ea):
        ni = ida_ua.insn_t()
        if not ida_ua.decode_insn(ni, h):
            continue
        m = ni.get_canon_mnem()
        if m == "retn":
            r = True
        elif m == "int":
            return False
    return r


def dump_lua():
    global PUSHFSTRING, RUNERROR
    print("--- lua ---")
    le = None
    tf = find_str("invalid argument #%d to '%s' (%s expected, got %s)", exact=True)
    if tf is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(tf))
        if xs:
            cf = ida_funcs.get_func(xs[0])
            if cf is not None:
                lst = []
                for h in idautils.Heads(cf.start_ea, cf.end_ea):
                    ni = ida_ua.insn_t()
                    if ida_ua.decode_insn(ni, h):
                        lst.append(ni)
                rv = {}
                for n, ni in enumerate(lst):
                    if ni.get_canon_mnem() != "call":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if not oo or oo[0].type != ida_ua.o_near:
                        continue
                    if any(lst[k].get_canon_mnem() == "int" for k in range(n + 1, min(len(lst), n + 4))):
                        rv[oo[0].addr] = rv.get(oo[0].addr, 0) + 1
                if rv:
                    rf = ida_funcs.get_func(max(rv, key=lambda k: rv[k]))
                    RUNERROR = max(rv, key=lambda k: rv[k])
                    if rf is not None:
                        rl = []
                        for h in idautils.Heads(rf.start_ea, rf.end_ea):
                            ni = ida_ua.insn_t()
                            if ida_ua.decode_insn(ni, h):
                                rl.append(ni)
                        tv = {}
                        for n, ni in enumerate(rl):
                            if ni.get_canon_mnem() != "call":
                                continue
                            oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                            if not oo or oo[0].type != ida_ua.o_near:
                                continue
                            hit = False
                            for k in range(max(0, n - 4), n):
                                if rl[k].get_canon_mnem() != "mov":
                                    continue
                                o2 = [rl[k][t] for t in range(6) if rl[k][t].type != ida_ua.o_void]
                                if len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 2 and o2[1].type == ida_ua.o_imm and (o2[1].value & 0xFFFFFFFFFFFFFFFF) == 4:
                                    hit = True
                                    break
                            if hit:
                                tv[oo[0].addr] = tv.get(oo[0].addr, 0) + 1
                        if tv:
                            th = max(tv, key=lambda k: tv[k])
                            if len(sorted(x.frm for x in idautils.XrefsTo(th))) > 100:
                                lv = {}
                                for y in idautils.XrefsTo(th):
                                    wf = ida_funcs.get_func(y.frm)
                                    if wf is None or (wf.end_ea - wf.start_ea) > 0x20:
                                        continue
                                    wl = []
                                    for h in idautils.Heads(wf.start_ea, wf.end_ea):
                                        ni = ida_ua.insn_t()
                                        if ida_ua.decode_insn(ni, h):
                                            wl.append((h, ni))
                                    idx = next((q for q, (a, _) in enumerate(wl) if a == y.frm), None)
                                    if idx is None:
                                        continue
                                    if sum(1 for _, ni in wl if ni.get_canon_mnem() == "call") != 1:
                                        continue
                                    for _, ni in wl[max(0, idx - 4):idx]:
                                        if ni.get_canon_mnem() != "mov":
                                            continue
                                        o2 = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                                        if len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 2 and o2[1].type == ida_ua.o_imm and (o2[1].value & 0xFFFFFFFFFFFFFFFF) == 2:
                                            lv[wf.start_ea] = lv.get(wf.start_ea, 0) + 1
                                            break
                                if lv:
                                    le = max(lv, key=lambda k: lv[k])
    if le is not None:
        print("LuaError = REBASE(0x%X)" % (le - BASE))
    else:
        print("LuaError: NO CHAIN")
    pf = None
    if le is not None:
        pv = {}
        for y in idautils.XrefsTo(le):
            wf = ida_funcs.get_func(y.frm)
            if wf is None:
                continue
            wl = []
            for h in idautils.Heads(wf.start_ea, wf.end_ea):
                ni = ida_ua.insn_t()
                if ida_ua.decode_insn(ni, h):
                    wl.append((h, ni))
            idx = next((q for q, (a, _) in enumerate(wl) if a == y.frm), None)
            if idx is None:
                continue
            for _, ni in wl[max(0, idx - 3):idx]:
                if ni.get_canon_mnem() != "call":
                    continue
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if not oo or oo[0].type != ida_ua.o_near:
                    continue
                tg = ida_funcs.get_func(oo[0].addr)
                if tg is None or (tg.end_ea - tg.start_ea) >= 0x60:
                    continue
                if _vararg_prologue(tg.start_ea) and _retn_no_int3(tg.start_ea):
                    pv[tg.start_ea] = pv.get(tg.start_ea, 0) + 1
        if pv:
            pf = max(pv, key=lambda k: pv[k])
            PUSHFSTRING = pf
    if pf is not None:
        print("LuaPushFString = REBASE(0x%X)" % (pf - BASE))
    else:
        print("LuaPushFString: NO VOTE")
    ns = None
    nf = find_str("Failed to create Lua state", exact=True)
    if nf is not None:
        nxs = sorted(x.frm for x in idautils.XrefsTo(nf))
        if nxs:
            js = sorted(x.frm for x in idautils.XrefsTo(nxs[0]) if x.iscode)
            if js:
                jf = ida_funcs.get_func(js[0])
                if jf is not None:
                    jl = []
                    for h in idautils.Heads(jf.start_ea, jf.end_ea):
                        ni = ida_ua.insn_t()
                        if ida_ua.decode_insn(ni, h):
                            jl.append((h, ni))
                    jdx = next((q for q, (a, _) in enumerate(jl) if a == js[0]), None)
                    if jdx is not None:
                        for q in range(jdx - 1, max(-1, jdx - 15), -1):
                            ni = jl[q][1]
                            if ni.get_canon_mnem() != "test":
                                continue
                            oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                            if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_reg and oo[0].reg == oo[1].reg:
                                for r in range(q - 1, max(-1, q - 7), -1):
                                    o3 = [jl[r][1][t] for t in range(6) if jl[r][1][t].type != ida_ua.o_void]
                                    if jl[r][1].get_canon_mnem() == "call" and o3 and o3[0].type == ida_ua.o_near:
                                        tg = ida_funcs.get_func(o3[0].addr)
                                        if tg is not None and (tg.end_ea - tg.start_ea) > 0x100:
                                            ns = tg.start_ea
                                        break
                                break
    if ns is not None:
        print("LuaNewState = REBASE(0x%X)" % (ns - BASE))
    else:
        print("LuaNewState: NO CHAIN")


def dump_lual():
    print("--- lual ---")
    ct = None
    tf = find_str("invalid argument #%d to '%s' (%s expected, got %s)", exact=True)
    if tf is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(tf))
        if xs:
            te = ida_funcs.get_func(xs[0])
            if te is not None:
                tx = sorted(x.frm for x in idautils.XrefsTo(te.start_ea))
                if tx:
                    cf = ida_funcs.get_func(tx[0])
                    if cf is not None and (cf.end_ea - cf.start_ea) < 0x100:
                        ct = cf.start_ea
    if ct is not None:
        print("LuaLCheckType = REBASE(0x%X)" % (ct - BASE))
    else:
        print("LuaLCheckType: NO CHAIN")
    gm = None
    gf = find_str("invalid argument #%d to '%s' (%s)", exact=True)
    if gf is not None:
        gxs = sorted(x.frm for x in idautils.XrefsTo(gf))
        if gxs:
            gf2 = ida_funcs.get_func(gxs[0])
            if gf2 is not None:
                if RUNERROR is None:
                    gm = gf2.start_ea
                else:
                    for h in idautils.Heads(gf2.start_ea, gf2.end_ea):
                        ni = ida_ua.insn_t()
                        if not ida_ua.decode_insn(ni, h):
                            continue
                        if ni.get_canon_mnem() != "call":
                            continue
                        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                        if oo and oo[0].type == ida_ua.o_near and oo[0].addr == RUNERROR:
                            gm = gf2.start_ea
                            break
    if gm is not None:
        print("LuaLGetMetafield = REBASE(0x%X)" % (gm - BASE))
    else:
        print("LuaLGetMetafield: NO CHAIN")


def dump_engine():
    import ida_segment
    print("--- luau ---")
    ls = find_str("%s: bytecode corrupted", exact=True)
    if ls is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(ls))
        lf = None
        for x in xs:
            f = ida_funcs.get_func(x)
            if f:
                lf = f.start_ea
                break
        if lf is not None:
            print("LoadSafe = REBASE(0x%X)" % (lf - BASE))
            from collections import Counter
            c = Counter()
            for x in idautils.XrefsTo(lf):
                f = ida_funcs.get_func(x.frm)
                if f and f.start_ea != lf:
                    c[f.start_ea] += 1
            if c:
                best, n = c.most_common(1)[0]
                if n >= 2:
                    print("LuaVMLoad = REBASE(0x%X)  [nrefs=%d]" % (best - BASE, n))
                else:
                    print("LuauVMLoad: weak max nrefs=%d" % n)
            else:
                print("LuauVMLoad: NO REFS")
        else:
            print("LoadSafe: XREF NOFUNC")
    else:
        print("LoadSafe: NO STRING")
    ur = find_str("/dev/urandom")
    if ur is not None:
        initf = None
        for x in sorted(x.frm for x in idautils.XrefsTo(ur)):
            f = ida_funcs.get_func(x)
            if f:
                initf = f.start_ea
                break
        d0, d1 = _data_range()
        table = None
        if initf is not None:
            callers = sorted(x.frm for x in idautils.XrefsTo(initf) if x.iscode)
            for cx in callers:
                cf = ida_funcs.get_func(cx)
                if cf is None:
                    continue
                ea = cf.start_ea
                while ea < cf.end_ea and table is None:
                    insn = ida_ua.insn_t()
                    if not ida_ua.decode_insn(insn, ea):
                        ea += 1
                        continue
                    if insn.get_canon_mnem() == "call":
                        tgt = None
                        for i in range(6):
                            op = insn[i]
                            if op.type == ida_ua.o_near:
                                tgt = op.addr
                                break
                        if tgt == initf:
                            sa = ea - 1
                            low = max(cf.start_ea, ea - 0x40)
                            while sa > low and table is None:
                                s2 = ida_ua.insn_t()
                                if ida_ua.decode_insn(s2, sa):
                                    if s2.get_canon_mnem() == "lea":
                                        for k in range(6):
                                            ok = s2[k]
                                            if ok.type == ida_ua.o_reg and ok.reg == 1:
                                                for m in range(6):
                                                    om = s2[m]
                                                    if om.type == ida_ua.o_mem and om.phrase == 5 and d0 <= om.addr < d1:
                                                        table = om.addr
                                                        break
                                sa -= 1
                    ea += insn.size if insn.size else 1
                if table is not None:
                    break
            if table is not None:
                print("BytecodeVerificationTableA = REBASE(0x%X)" % (table - BASE))
            else:
                print("BytecodeVerificationTableA: NO TABLE LEA")
    else:
        print("BytecodeVerificationTableA: NO STRING")
    av = find_str("assignVal")
    if av is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(av))
        if len(xs) >= 7:
            hf = ida_funcs.get_func(xs[6])
            if hf is not None:
                import ida_strlist, ida_bytes
                facet = set()
                qty = ida_strlist.get_strlist_qty()
                si = ida_strlist.string_info_t()
                for i in range(qty):
                    if not ida_strlist.get_strlist_item(si, i):
                        continue
                    raw = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
                    if raw == b"Invalid Facet Access":
                        facet.add(si.ea)
                got = None
                ea = hf.start_ea
                while ea < hf.end_ea and got is None:
                    insn = ida_ua.insn_t()
                    if not ida_ua.decode_insn(insn, ea):
                        ea += 1
                        continue
                    if insn.get_canon_mnem() == "cmp":
                        ops = [insn[j] for j in range(6) if insn[j].type != ida_ua.o_void]
                        if len(ops) == 2 and ops[0].type == ida_ua.o_reg and ops[1].type == ida_ua.o_imm and (ops[1].value & 0xFFFFFFFFFFFFFFFF) == 3:
                            sa = ea + insn.size
                            for _ in range(12):
                                s2 = ida_ua.insn_t()
                                if not ida_ua.decode_insn(s2, sa):
                                    break
                                if s2.get_canon_mnem() == "call":
                                    for k in range(6):
                                        op = s2[k]
                                        if op.type == ida_ua.o_near and _func_refs_str(op.addr, facet):
                                            got = op.addr
                                            break
                                    break
                                sa += s2.size
                    ea += insn.size if insn.size else 1
                if got is not None:
                    print("GetGlobalState = REBASE(0x%X)" % (got - BASE))
                else:
                    print("GetGlobalState: NO GUARD-CALL")
            else:
                print("GetGlobalState: HOST NOFUNC")
        else:
            print("GetGlobalState: only %d assignVal xrefs" % len(xs))
    else:
        print("GetGlobalState: NO STRING")
    prt = None
    if PUSHFSTRING is not None:
        pff = ida_funcs.get_func(PUSHFSTRING)
        if pff is not None:
            core = None
            for h in idautils.Heads(pff.start_ea, pff.end_ea):
                ni = ida_ua.insn_t()
                if not ida_ua.decode_insn(ni, h):
                    continue
                if ni.get_canon_mnem() != "call":
                    continue
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if oo and oo[0].type == ida_ua.o_near:
                    core = oo[0].addr
                    break
            if core is not None:
                print("LuaOPushFString = REBASE(0x%X)" % (core - BASE))
            else:
                print("LuaOPushFString: NO CORE")
            vsn = None
            if core is not None:
                cf2 = ida_funcs.get_func(core)
                if cf2 is not None:
                    for h in idautils.Heads(cf2.start_ea, cf2.end_ea):
                        ni = ida_ua.insn_t()
                        if not ida_ua.decode_insn(ni, h):
                            continue
                        if ni.get_canon_mnem() != "call":
                            continue
                        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                        if not oo or oo[0].type != ida_ua.o_near:
                            continue
                        vf = ida_funcs.get_func(oo[0].addr)
                        if vf is None:
                            continue
                        vsz = vf.end_ea - vf.start_ea
                        if vsz < 0x150 or vsz > 0x350:
                            continue
                        nvc = 0
                        for h2 in idautils.Heads(vf.start_ea, vf.end_ea):
                            nj = ida_ua.insn_t()
                            if ida_ua.decode_insn(nj, h2) and nj.get_canon_mnem() == "call":
                                nvc += 1
                        if nvc < 5:
                            continue
                        nvx = len(sorted(x.frm for x in idautils.XrefsTo(vf.start_ea)))
                        if 25 <= nvx <= 40:
                            vsn = vf.start_ea
                            break
            if vsn is not None:
                cand = {}
                for y in idautils.XrefsTo(vsn):
                    wf = ida_funcs.get_func(y.frm)
                    if wf is None:
                        continue
                    wsz = wf.end_ea - wf.start_ea
                    if wsz < 0x100 or wsz > 0x300:
                        continue
                    sp = set()
                    ck = False
                    rt = False
                    i3 = False
                    n = 0
                    cal = set()
                    for h in idautils.Heads(wf.start_ea, wf.end_ea):
                        ni = ida_ua.insn_t()
                        if not ida_ua.decode_insn(ni, h):
                            continue
                        m = ni.get_canon_mnem()
                        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                        if n < 8 and m == "mov" and len(oo) == 2 and oo[0].type == ida_ua.o_displ and oo[0].reg == 4 and oo[1].type == ida_ua.o_reg:
                            sp.add((oo[0].addr, oo[1].reg))
                        n += 1
                        if m == "xor" and len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_reg and (oo[0].reg == 4 or oo[1].reg == 4):
                            ck = True
                        if m == "retn":
                            rt = True
                        if m == "int":
                            i3 = True
                        if m == "call" and oo and oo[0].type == ida_ua.o_near:
                            cal.add(oo[0].addr)
                    if not ((0x10, 2) in sp and (0x18, 8) in sp and (0x20, 9) in sp and ck and rt and i3):
                        continue
                    for c in cal:
                        ncx = len(sorted(x.frm for x in idautils.XrefsTo(c)))
                        if 80 <= ncx <= 95:
                            cand[wf.start_ea] = cand.get(wf.start_ea, 0) + 1
                            break
                if cand:
                    prt = max(cand, key=lambda k: cand[k])
    if prt is not None:
        print("print = REBASE(0x%X)" % (prt - BASE))
    else:
        print("print: NO CHAIN")
    rn = None
    if RUNERROR is not None:
        rn = RUNERROR
    if rn is not None:
        print("RunError = REBASE(0x%X)" % (rn - BASE))
    else:
        print("RunError: NO CHAIN")
    cks = None
    ps2 = None
    dmn = None
    nilo = None
    wref = find_str("Attempt to migrate WeakObjectRef across VM boundary", exact=True)
    if wref is not None:
        wxs = sorted(x.frm for x in idautils.XrefsTo(wref))
        if wxs:
            wf = ida_funcs.get_func(wxs[0])
            if wf is not None:
                wl = []
                for h in idautils.Heads(wf.start_ea, wf.end_ea):
                    ni = ida_ua.insn_t()
                    if ida_ua.decode_insn(ni, h):
                        wl.append((h, ni))
                cv = {}
                for n, (a, ni) in enumerate(wl):
                    if ni.get_canon_mnem() != "call":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if not oo or oo[0].type != ida_ua.o_near:
                        continue
                    r2v = None
                    for k in range(max(0, n - 4), n):
                        m2 = wl[k][1].get_canon_mnem()
                        o2 = [wl[k][1][t] for t in range(6) if wl[k][1][t].type != ida_ua.o_void]
                        if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 2:
                            if o2[1].type == ida_ua.o_imm and (o2[1].value & 0xFFFFFFFFFFFFFFFF) == 1:
                                r2v = 1
                                break
                            if o2[1].type == ida_ua.o_reg:
                                for j in range(max(0, k - 4), k):
                                    m3 = wl[j][1].get_canon_mnem()
                                    o3 = [wl[j][1][t] for t in range(6) if wl[j][1][t].type != ida_ua.o_void]
                                    if m3 == "mov" and len(o3) == 2 and o3[0].type == ida_ua.o_reg and o3[0].reg == o2[1].reg and o3[1].type == ida_ua.o_imm and (o3[1].value & 0xFFFFFFFFFFFFFFFF) == 1:
                                        r2v = 1
                                        break
                                if r2v is not None:
                                    break
                    if r2v == 1:
                        cv[oo[0].addr] = cv.get(oo[0].addr, 0) + 1
                if cv:
                    cks = max(cv, key=lambda k: cv[k])
                for n, (a, ni) in enumerate(wl):
                    if ni.get_canon_mnem() != "call":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if not oo or oo[0].type != ida_ua.o_near:
                        continue
                    hit = False
                    for k in range(max(0, n - 4), n):
                        m2 = wl[k][1].get_canon_mnem()
                        o2 = [wl[k][1][t] for t in range(6) if wl[k][1][t].type != ida_ua.o_void]
                        if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 2 and o2[1].type == ida_ua.o_imm and (o2[1].value & 0xFFFFFFFFFFFFFFFF) == 0xFFFFFFFFFFFFD8F0:
                            hit = True
                            break
                    if hit:
                        ps2 = oo[0].addr
                        break
                dleas = []
                for n, (a, ni) in enumerate(wl):
                    if ni.get_canon_mnem() != "lea":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_mem and _pair_name(oo[1].addr) is None:
                            cmpd = False
                            for k in range(n + 1, min(len(wl), n + 5)):
                                m2 = wl[k][1].get_canon_mnem()
                                o2 = [wl[k][1][t] for t in range(6) if wl[k][1][t].type != ida_ua.o_void]
                                if m2 == "cmp" and any(x.type == ida_ua.o_reg and x.reg == oo[0].reg for x in o2):
                                    cmpd = True
                                    break
                            dleas.append((oo[1].addr, cmpd))
                for addr, cmpd in dleas:
                    if cmpd and dmn is None:
                        dmn = addr
                rest = [addr for addr, cmpd in dleas if addr != dmn]
                if dmn is not None and len(rest) == 1:
                    nilo = rest[0]
    if cks is not None:
        print("LuaCheckStack = REBASE(0x%X)" % (cks - BASE))
    else:
        print("LuaCheckStack: NO VOTE")
    if ps2 is not None:
        print("Pseudo2Addr = REBASE(0x%X)" % (ps2 - BASE))
    else:
        print("Pseudo2Addr: NO CHAIN")
    if dmn is not None:
        print("LuaHDummyNode = REBASE(0x%X)" % (dmn - BASE))
    else:
        print("LuaHDummyNode: NO LEA")
    if nilo is not None:
        print("LuaONilObject = REBASE(0x%X)" % (nilo - BASE))
    else:
        print("LuaONilObject: NO LEA")
    otbl = None
    it = find_str("iterate over", exact=True)
    if it is not None:
        fns = {}
        for y in idautils.XrefsTo(it):
            bf = ida_funcs.get_func(y.frm)
            if bf is not None:
                fns.setdefault(bf.start_ea, []).append(y.frm)
        bodies = [fs for fs, xs in fns.items() if len(xs) >= 3]
        tv2 = {}
        for fs in bodies:
            bf = ida_funcs.get_func(fs)
            bl = []
            for h in idautils.Heads(bf.start_ea, bf.end_ea):
                ni = ida_ua.insn_t()
                if ida_ua.decode_insn(ni, h):
                    bl.append((h, ni))
            for n, (a, ni) in enumerate(bl):
                if ni.get_canon_mnem() != "call":
                    continue
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if not oo or oo[0].type != ida_ua.o_near:
                    continue
                la = None
                im = None
                for k in range(max(0, n - 6), n):
                    m2 = bl[k][1].get_canon_mnem()
                    o2 = [bl[k][1][t] for t in range(6) if bl[k][1][t].type != ida_ua.o_void]
                    if m2 == "lea" and len(o2) == 2 and o2[1].type == ida_ua.o_mem:
                        la = o2[1].addr
                    if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg in (2, 8, 9) and o2[1].type == ida_ua.o_imm and 0 < (o2[1].value & 0xFFFFFFFFFFFFFFFF) < 300:
                        im = o2[1].value & 0xFFFFFFFFFFFFFFFF
                if la is not None and im is not None:
                    tv2.setdefault((oo[0].addr, la), set()).add(im)
        bestn = 0
        for (tgt, abs), ims in tv2.items():
            if len(ims) >= 3 and len(ims) > bestn:
                bestn = len(ims)
                otbl = abs
    _opc = dump_opcode_table()
    if _opc is None:
        if otbl is not None:
            print("OpcodeLookUpTable = REBASE(0x%X)" % (otbl - BASE))
        else:
            print("OpcodeLookUpTable: NO VOTE")
    ex = None
    if otbl is not None:
        twins = {}
        for y in idautils.XrefsTo(otbl):
            bf = ida_funcs.get_func(y.frm)
            if bf is not None:
                twins.setdefault(bf.start_ea, []).append(y.frm)
        twinset = [fs for fs, xs in twins.items() if len(xs) >= 3]
        th = {}
        for fs in twinset:
            for y in idautils.XrefsTo(fs):
                ji = ida_ua.insn_t()
                if not ida_ua.decode_insn(ji, y.frm):
                    continue
                if ji.get_canon_mnem() != "jmp":
                    continue
                oo = [ji[t] for t in range(6) if ji[t].type != ida_ua.o_void]
                if not oo or oo[0].type != ida_ua.o_near or oo[0].addr != fs:
                    continue
                wf = ida_funcs.get_func(y.frm)
                if wf is not None and (wf.end_ea - wf.start_ea) <= 0x20:
                    th[wf.start_ea] = th.get(wf.start_ea, 0) + 1
        if th:
            ex = max(th, key=lambda k: th[k])
    if ex is not None:
        print("LuauExecute = REBASE(0x%X)" % (ex - BASE))
    else:
        print("LuauExecute: NO PAIR")
    tcl = None
    ts = find_str("table has a protected metatable", exact=True)
    if ts is not None:
        txs = sorted(x.frm for x in idautils.XrefsTo(ts))
        if len(txs) >= 2:
            tf2 = ida_funcs.get_func(txs[1])
            if tf2 is not None:
                tcl = tf2.start_ea
    if tcl is not None:
        print("TClone = REBASE(0x%X)" % (tcl - BASE))
    else:
        print("TClone: NO STRING")
    hcl = None
    if tcl is not None:
        hf = ida_funcs.get_func(tcl)
        if hf is not None:
            hl = []
            for h in idautils.Heads(hf.start_ea, hf.end_ea):
                ni = ida_ua.insn_t()
                if ida_ua.decode_insn(ni, h):
                    hl.append((h, ni))
            calls = []
            for n, (a, ni) in enumerate(hl):
                if ni.get_canon_mnem() != "call":
                    continue
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if not oo or oo[0].type != ida_ua.o_near:
                    continue
                calls.append((n, oo[0].addr))
            if dmn is not None:
                dmnhit = [(n, tgt) for n, tgt in calls if _func_refs_addr(tgt, dmn)]
                if len(dmnhit) == 1:
                    hcl = dmnhit[0][1]
                elif len(dmnhit) > 1:
                    taghit = []
                    for n, tgt in dmnhit:
                        for k in range(n + 1, min(len(hl), n + 9)):
                            m2 = hl[k][1].get_canon_mnem()
                            o2 = [hl[k][1][t] for t in range(6) if hl[k][1][t].type != ida_ua.o_void]
                            if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_displ and o2[0].reg == 4 and o2[1].type == ida_ua.o_imm and (o2[1].value & 0xFFFFFFFF) == 7:
                                taghit.append(tgt)
                                break
                    if len(taghit) == 1:
                        hcl = taghit[0]
            if hcl is None:
                for n, tgt in calls:
                    hit28 = False
                    for k in range(max(0, n - 4), n):
                        m2 = hl[k][1].get_canon_mnem()
                        o2 = [hl[k][1][t] for t in range(6) if hl[k][1][t].type != ida_ua.o_void]
                        if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 2 and o2[1].type == ida_ua.o_displ and o2[1].addr == 0x28:
                            hit28 = True
                            break
                    if hit28:
                        hcl = tgt
                        break
    if hcl is not None:
        print("HClone = REBASE(0x%X)" % (hcl - BASE))
    else:
        print("HClone: NO CALL")
    ngc = None
    if hcl is not None:
        hf = ida_funcs.get_func(hcl)
        if hf is not None:
            hl = []
            for h in idautils.Heads(hf.start_ea, hf.end_ea):
                ni = ida_ua.insn_t()
                if ida_ua.decode_insn(ni, h):
                    hl.append((h, ni))
            cands = []
            for n, (a, ni) in enumerate(hl):
                if ni.get_canon_mnem() != "call":
                    continue
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if not oo or oo[0].type != ida_ua.o_near:
                    continue
                r9set = False
                spill = False
                for k in range(max(0, n - 10), n):
                    m2 = hl[k][1].get_canon_mnem()
                    o2 = [hl[k][1][t] for t in range(6) if hl[k][1][t].type != ida_ua.o_void]
                    if len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 9 and m2 in ("mov", "movzx", "lea"):
                        r9set = True
                    if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_displ and o2[0].reg == 4 and o2[0].addr == 0x20:
                        spill = True
                if r9set and spill:
                    cands.append(oo[0].addr)
            hit = []
            for t in cands:
                tf = ida_funcs.get_func(t)
                if tf is None:
                    continue
                for h in idautils.Heads(tf.start_ea, tf.end_ea):
                    ni = ida_ua.insn_t()
                    if not ida_ua.decode_insn(ni, h):
                        continue
                    if ni.get_canon_mnem() != "call":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if oo and oo[0].type == ida_ua.o_near and oo[0].addr in cands and oo[0].addr != t:
                        hit.append(t)
                        break
            if len(hit) == 1:
                ngc = hit[0]
    if ngc is not None:
        print("NewPage = REBASE(0x%X)" % (ngc - BASE))
    else:
        print("NewPage: NO CALL")
    kt = None
    ks = find_str("Trying to call method on object of type")
    if ks is not None:
        kxs = sorted(x.frm for x in idautils.XrefsTo(ks))
        if kxs:
            kf = ida_funcs.get_func(kxs[0])
            if kf is not None:
                dseg = ida_segment.get_segm_by_name(".data")
                if dseg is not None:
                    q0, q1 = int(dseg.start_ea), int(dseg.end_ea)
                    kl = []
                    for h in idautils.Heads(kf.start_ea, kf.end_ea):
                        ni = ida_ua.insn_t()
                        if ida_ua.decode_insn(ni, h):
                            kl.append((h, ni))
                    for n, (a, ni) in enumerate(kl):
                        if ni.get_canon_mnem() != "lea":
                            continue
                        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                        if len(oo) != 2 or oo[1].type != ida_ua.o_mem or not (q0 <= oo[1].addr < q1):
                            continue
                        for k in range(n + 1, min(len(kl), n + 9)):
                            o2 = [kl[k][1][t] for t in range(6) if kl[k][1][t].type != ida_ua.o_void]
                            if any(x.type == ida_ua.o_phrase for x in o2):
                                kt = oo[1].addr
                                break
                        if kt is not None:
                            break
    if kt is not None:
        print("KTable = REBASE(0x%X)" % (kt - BASE))
    else:
        print("KTable: NO LEA")
    print("--- scriptcontext ---")
    rf = None
    rq = find_str("Cannot require a non-RobloxScript module from a RobloxScript", exact=True)
    if rq is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(rq))
        for x in xs:
            f = ida_funcs.get_func(x)
            if f:
                rf = f
                break
        if rf is not None:
            branch = None
            pos = xs[0] - 1
            low = max(rf.start_ea, xs[0] - 0x1000)
            while pos > low:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, pos):
                    m = insn.get_canon_mnem()
                    if m.startswith("j") and m != "jmp" and m != "jmpshort":
                        for i in range(6):
                            op = insn[i]
                            if op.type == ida_ua.o_near and op.addr == xs[0]:
                                branch = pos
                                break
                    if branch is not None:
                        break
                pos -= 1
            got = None
            if branch is not None:
                pos = branch - 1
                low2 = max(rf.start_ea, branch - 0x200)
                while pos > low2:
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, pos):
                        if insn.get_canon_mnem() == "cmp":
                            ops = [insn[j] for j in range(6) if insn[j].type != ida_ua.o_void]
                            if len(ops) == 2 and ops[0].type == ida_ua.o_displ and ops[1].type == ida_ua.o_imm:
                                d = ops[0].addr
                                if 0x100 <= d <= 0x4000 and (ops[1].value & 0xFFFFFFFFFFFFFFFF) == 0:
                                    got = d
                                    break
                    pos -= 1
            if got is not None:
                print("RequireBypass = 0x%X" % got)
            else:
                print("RequireBypass: NO CMP WALK")
        else:
            print("Require: XREF NOFUNC")
    else:
        print("Require: NO STRING")
    print("--- Capabilities ---")
    masks = {0x20000000, 0x30000000, 0x60000000, 0x70000000, 0x10000000}
    pick = None
    for _, t in (_calls_in(rf.start_ea, rf.end_ea) if rf is not None else []):
        tf = ida_funcs.get_func(t)
        if not tf:
            continue
        ea = tf.start_ea
        scanned = 0
        while ea < tf.end_ea and scanned < 0x800:
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                ea += 1
                continue
            if insn.get_canon_mnem() == "mov":
                ops = [insn[j] for j in range(6) if insn[j].type != ida_ua.o_void]
                if len(ops) == 2 and ops[1].type == ida_ua.o_imm:
                    if (ops[1].value >> 32) & 0xFFFFFFFF in masks:
                        pick = t
                        break
            ea += insn.size if insn.size else 1
            scanned += 8
        if pick is not None:
            break
    if pick is not None:
        import ida_hexrays
        try:
            txt = str(ida_hexrays.decompile(pick))
        except Exception:
            txt = ""
        if "switch" in txt:
            print("GetCapabilities = REBASE(0x%X)" % (pick - BASE))
        else:
            print("GetCapabilities: UNCONFIRMED 0x%X" % pick)
    else:
        print("GetCapabilities: NO MASK HIT")
    structcap = None
    if pick is not None:
        wrap = None
        for x in idautils.XrefsTo(pick):
            cf = ida_funcs.get_func(x.frm)
            if cf is None:
                continue
            ea = cf.start_ea
            while ea < cf.end_ea and wrap is None:
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    ea += 1
                    continue
                if insn.get_canon_mnem() == "and":
                    ops = [insn[j] for j in range(6) if insn[j].type != ida_ua.o_void]
                    if len(ops) == 2 and ops[0].type == ida_ua.o_reg and ops[1].type == ida_ua.o_imm and (ops[1].value & 0xFFFFFFFF) == 0xFFFFFF00:
                        wrap = cf.start_ea
                ea += insn.size if insn.size else 1
            if wrap is not None:
                break
        if wrap is not None:
            wf = ida_funcs.get_func(wrap)
            lst = []
            for h in idautils.Heads(wf.start_ea, wf.end_ea):
                ni = ida_ua.insn_t()
                if ida_ua.decode_insn(ni, h):
                    lst.append(ni)
            arg2 = None
            for ni in lst[:15]:
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if ni.get_canon_mnem() == "mov" and len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_reg and oo[1].reg == 2:
                    arg2 = oo[0].reg
                    break
            rm = None
            ai = None
            for n, ni in enumerate(lst):
                if ni.get_canon_mnem() != "and":
                    continue
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_imm and (oo[1].value & 0xFFFFFFFF) == 0xFFFFFF00:
                    rm = oo[0].reg
                    ai = n
                    break
            ra = None
            oi = None
            if ai is not None:
                for n in range(ai + 1, len(lst)):
                    ni = lst[n]
                    if ni.get_canon_mnem() != "or":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_reg and (oo[0].reg == rm or oo[1].reg == rm):
                        ra = oo[1].reg if oo[0].reg == rm else oo[0].reg
                        oi = n
                        break
            kk = None
            sp = None
            if oi is not None:
                for n in range(oi + 1, len(lst)):
                    ni = lst[n]
                    if ni.get_canon_mnem() != "mov":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if len(oo) == 2 and oo[0].type == ida_ua.o_displ and oo[0].reg == 4 and oo[1].type == ida_ua.o_reg and oo[1].reg == ra:
                        kk = oo[0].addr
                        sp = n
                        break
            xx = None
            ld = None
            if sp is not None:
                for n in range(sp + 1, len(lst)):
                    ni = lst[n]
                    if ni.get_canon_mnem() != "movups":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_displ and oo[1].reg == 4 and oo[1].addr == kk:
                        xx = oo[0].reg
                        ld = n
                        break
            if ld is not None:
                for n in range(ld + 1, len(lst)):
                    ni = lst[n]
                    if ni.get_canon_mnem() != "movups":
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if len(oo) == 2 and oo[0].type == ida_ua.o_displ and oo[0].reg == arg2 and oo[1].type == ida_ua.o_reg and oo[1].reg == xx:
                        structcap = oo[0].addr
                        break
    if structcap is not None:
        print("Capability = 0x%X" % structcap)
    else:
        print("Capability: NO MERGE WALK")
    print("--- classdescriptor ---")
    ph3 = find_str("data_model_service_init_part3_begin")
    if ph3 is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(ph3))
        hf = None
        for x in xs:
            f = ida_funcs.get_func(x)
            if f:
                hf = f
                break
        if hf is not None:
            import ida_segment
            text = ida_segment.get_segm_by_name(".text")
            notcode = int(text.end_ea)
            cands = []
            ea = hf.start_ea
            while ea < hf.end_ea:
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    ea += 1
                    continue
                if insn.get_canon_mnem() == "lea":
                    ops = [insn[j] for j in range(6) if insn[j].type != ida_ua.o_void]
                    if len(ops) == 2 and ops[0].type == ida_ua.o_reg and ops[0].reg == 1 and ops[1].type == ida_ua.o_mem and ops[1].phrase == 5 and ops[1].addr >= notcode:
                        sa = ea + insn.size
                        for _ in range(5):
                            s2 = ida_ua.insn_t()
                            if not ida_ua.decode_insn(s2, sa):
                                break
                            if s2.get_canon_mnem() == "call":
                                tgt = None
                                for k in range(6):
                                    ok = s2[k]
                                    if ok.type == ida_ua.o_near:
                                        tgt = ok.addr
                                        break
                                if tgt is not None:
                                    sa2 = sa + s2.size
                                    for _ in range(40):
                                        s3 = ida_ua.insn_t()
                                        if not ida_ua.decode_insn(s3, sa2):
                                            break
                                        m3 = s3.get_canon_mnem()
                                        if m3 == "call":
                                            break
                                        o3 = [s3[j] for j in range(6) if s3[j].type != ida_ua.o_void]
                                        if m3 == "mov" and len(o3) == 2 and o3[0].type == ida_ua.o_reg and o3[0].reg == 8 and o3[1].type == ida_ua.o_reg and o3[1].reg == 0:
                                            sa3 = sa2 + s3.size
                                            for _ in range(12):
                                                s4 = ida_ua.insn_t()
                                                if not ida_ua.decode_insn(s4, sa3):
                                                    break
                                                if s4.get_canon_mnem() == "call":
                                                    cands.append(tgt)
                                                    break
                                                sa3 += s4.size
                                            break
                                        sa2 += s3.size
                                break
                            sa += s2.size
                ea += insn.size if insn.size else 1
            uniq = sorted(set(cands))
            if len(uniq) == 1:
                print("HashLookUp = REBASE(0x%X)" % (uniq[0] - BASE))
            else:
                print("HashLookUp: DEFERRED (%d candidates)" % len(uniq))
        else:
            print("HashLookUp: HOST NOFUNC")
    else:
        print("HashLookUp: NO STRING")
    uc = find_str("Unable to cast %s to %s", exact=True)
    if uc is not None:
        import ida_search
        ufuncs = set()
        for x in idautils.XrefsTo(uc):
            f = ida_funcs.get_func(x.frm)
            if f:
                ufuncs.add(f.start_ea)
        data = None
        seenfn = set()
        ea = 0x1000
        for _ in range(500):
            r = ida_search.find_imm(ea, ida_search.SEARCH_DOWN, 16777619)
            if not isinstance(r, tuple):
                break
            ea = r[0]
            if ea == 0xFFFFFFFFFFFFFFFF:
                break
            f = ida_funcs.get_func(ea)
            if f and f.start_ea not in seenfn:
                seenfn.add(f.start_ea)
                for x in idautils.XrefsTo(f.start_ea):
                    cf = ida_funcs.get_func(x.frm)
                    if cf and cf.start_ea in ufuncs and _datasite_ok(x.frm):
                        data = f.start_ea
                        break
                if data is not None:
                    break
            ea += 1
        if data is not None:
            print("GetPropertyData = REBASE(0x%X)" % (data - BASE))
        else:
            print("GetPropertyData: NO FNV CALLER")
    else:
        print("GetPropertyData: NO STRING")
    cd = find_str("Could not find property descriptor", exact=True)
    if cd is not None:
        cands = []
        for x in idautils.XrefsTo(cd):
            f = ida_funcs.get_func(x.frm)
            if f:
                cands.append(f)
        cands.sort(key=lambda f: f.end_ea - f.start_ea)
        desc = None
        for cf in cands:
            ea = cf.start_ea
            while ea < cf.end_ea and desc is None:
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    ea += 1
                    continue
                for i in range(6):
                    op = insn[i]
                    if op.type == ida_ua.o_displ and op.addr == 0x1D8:
                        sa = ea + insn.size
                        for _ in range(10):
                            s2 = ida_ua.insn_t()
                            if not ida_ua.decode_insn(s2, sa):
                                break
                            if s2.get_canon_mnem() == "call":
                                for k in range(6):
                                    ok = s2[k]
                                    if ok.type == ida_ua.o_near:
                                        desc = ok.addr
                                        break
                                break
                            sa += s2.size
                        break
                ea += insn.size if insn.size else 1
            if desc is not None:
                break
        if desc is not None:
            print("GetPropertyDescriptor = REBASE(0x%X)" % (desc - BASE))
        else:
            print("GetPropertyDescriptor: NO MAP CALL")
    else:
        print("GetPropertyDescriptor: NO STRING")
    print("--- engine misc ---")
    dump_func("ScriptContextResume", "resume script in this context")
    dump_identity()
    print("--- taskscheduler ---")
    ap = find_str("AppInitializer", exact=True)
    if ap is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(ap))
        af = None
        for x in xs:
            f = ida_funcs.get_func(x)
            if f:
                af = f
                break
        if af is not None:
            import ida_segment
            data = ida_segment.get_segm_by_name(".data")
            d0, d1 = int(data.start_ea), int(data.end_ea)
            ptr = None
            ea = af.start_ea
            while ea < af.end_ea:
                insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(insn, ea):
                    ea += 1
                    continue
                if insn.get_canon_mnem() == "lea":
                    for i in range(6):
                        op = insn[i]
                        if op.type == ida_ua.o_mem and op.phrase == 5 and op.addr == ap:
                            sa = ea + insn.size
                            for _ in range(16):
                                s2 = ida_ua.insn_t()
                                if not ida_ua.decode_insn(s2, sa):
                                    break
                                if s2.get_canon_mnem() == "call":
                                    break
                                for k in range(6):
                                    ok = s2[k]
                                    if ok.type == ida_ua.o_mem and ok.phrase == 5 and d0 <= ok.addr < d1:
                                        ptr = ok.addr
                                sa += s2.size
                            break
                    if ptr is not None:
                        break
                ea += insn.size if insn.size else 1
            if ptr is not None:
                print("TaskScheduler = REBASE(0x%X)" % (ptr - BASE))
            else:
                print("TaskScheduler: NO SLOT")
        else:
            print("TaskScheduler: HOST NOFUNC")
    else:
        print("TaskScheduler: NO STRING")
    dump_taskschedulerfps()


def _dword_load_target(ea):
    import ida_bytes
    import ida_segment
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        return None
    if insn.get_canon_mnem() != "mov":
        return None
    ops = [insn[j] for j in range(6) if insn[j].type != ida_ua.o_void]
    if len(ops) != 2 or ops[1].type != ida_ua.o_mem or ops[1].phrase != 5:
        return None
    data = ida_segment.get_segm_by_name(".data")
    if not (int(data.start_ea) <= ops[1].addr < int(data.end_ea)):
        return None
    if insn.size == 6:
        return ops[1].addr
    if insn.size == 7 and (ida_bytes.get_byte(ea) & 0x48) != 0x48:
        return ops[1].addr
    return None


def dump_taskschedulerfps():
    s = find_str("TS::Step", exact=True)
    if not s:
        print("TaskSchedulerTargetFPS: NO STRING")
        return
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    f = None
    for x in xs:
        f = ida_funcs.get_func(x)
        if f:
            break
    if f is None:
        print("TaskSchedulerTargetFPS: HOST NOFUNC")
        return
    best, bestgap = None, 999
    ea = f.start_ea
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            ea += 1
            continue
        if insn.get_canon_mnem() == "call":
            sa = ea + insn.size
            for gap in range(6):
                tgt = _dword_load_target(sa)
                if tgt is not None:
                    if gap < bestgap:
                        bestgap = gap
                        best = tgt
                    break
                nx = ida_ua.insn_t()
                if not ida_ua.decode_insn(nx, sa):
                    break
                sa += nx.size
        ea += insn.size if insn.size else 1
    if best is not None:
        print("TaskSchedulerTargetFPS = REBASE(0x%X)" % (best - BASE))
    else:
        print("TaskSchedulerTargetFPS: NO PAIR")


def dump_raycast():
    print("--- raycast ---")
    dump_func("ShapeCast", "Attempt to shapecast with distance")
    dump_func("SphereCast", "Attempt to spherecast with radius", n=2)
    dump_func_last("BlockCast", "Attempt to blockcast with side length", n=2)
    s = find_str("Raycast", exact=True)
    if not s:
        print("WorldRootRaycast: NO STRING")
        return
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        print("WorldRootRaycast: NO XREF")
        return
    wrapper = func_of(xs[0])
    if wrapper is None:
        print("WorldRootRaycast: xref not in func")
        return
    callers = sorted(x.frm for x in idautils.XrefsTo(wrapper) if x.iscode)
    if not callers:
        print("WorldRootRaycast: NO CALLER")
        return
    cf = ida_funcs.get_func(callers[0])
    if not cf:
        print("WorldRootRaycast: caller not in func")
        return
    ea, fend = cf.start_ea, cf.end_ea
    hit = None
    while ea < fend:
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            ea += 1
            continue
        if insn.get_canon_mnem() == "lea":
            for i in range(6):
                op = insn[i]
                if op.type == ida_ua.o_mem and op.phrase == 5:
                    tf = ida_funcs.get_func(op.addr)
                    if tf and tf.start_ea == op.addr and tf.end_ea - tf.start_ea >= 0x100:
                        hit = tf.start_ea
                        break
            if hit is not None:
                break
        ea += insn.size if insn.size else 1
    if hit is None:
        print("WorldRootRaycast: NO CANDIDATE")
        return
    print("WorldRootRaycast = REBASE(0x%X)" % (hit - BASE))
    fcv = find_vtable("??_7FastClusterEntity@Graphics@RBX@@6B@")
    if fcv is not None:
        print("FastClusterEntityVTable = REBASE(0x%X)" % (fcv - BASE))


def dump_rbxtransport():
    print("--- rbxtransport ---")
    cv = find_vtable("??_7RbxTransportConnection@NetworkBase@RBX@@6B@")
    if cv is not None:
        print("ClientVTable = REBASE(0x%X)" % (cv - BASE))
        slot0 = int(ida_bytes.get_qword(cv))
        if _is_func_start(slot0):
            print("ClientDestructor = REBASE(0x%X)" % (slot0 - BASE))
        else:
            print("ClientDestructor: BAD SLOT0 0x%X" % slot0)
    else:
        print("ClientVTable: NO SYMBOL")
        print("ClientDestructor: NO VTABLE")
    av = find_vtable("??_7RtcAppConnection@Impl@RbxTransport@RBX@@6B@")
    if av is not None:
        print("AppVTable = REBASE(0x%X)" % (av - BASE))
        aslot0 = int(ida_bytes.get_qword(av))
        if _is_func_start(aslot0):
            print("AppDestructor = REBASE(0x%X)" % (aslot0 - BASE))
        else:
            print("AppDestructor: BAD SLOT0 0x%X" % aslot0)
    else:
        print("AppVTable: NO SYMBOL")
        print("AppDestructor: NO VTABLE")
    dump_symbol("ClientRtti", "??_R4RbxTransportConnection@NetworkBase@RBX@@6B@")
    dump_symbol("AppRtti", "??_R4RtcAppConnection@Impl@RbxTransport@RBX@@6B@")
    dump_func("ClientSend", "Trying to send on a not ready channel!")
    crecv = _find_client_receive()
    if crecv is not None:
        print("ClientReceive = REBASE(0x%X)" % (crecv - BASE))
    else:
        print("ClientReceive: NO SLOT")
    csend = _anchor_func("Trying to send on a not ready channel!")
    ccfg = _call_in_region("Failed to open send channel {}!", csend)
    print("ClientChannelConfig = REBASE(0x%X)" % (ccfg - BASE) if ccfg is not None else "ClientChannelConfig: NO CALL")
    appsend = _vtable_slot(av, 8)
    print("AppSend = REBASE(0x%X)" % (appsend - BASE) if appsend is not None else "AppSend: NO SLOT")
    dump_func_any("AppReceive", [
        "[DFLog::RbxTransportRnaExpConnection] {}. receivePop. Channel {} not found",
        "The state object field '{}' is not exported, returning nil.",
    ])
    dump_func_any("AppReceiveMaxBytes", [
        "[DFLog::RbxTransportRnaExpConnection] {}. receivePopMaxBytes. ChannelId {}, maxBytes {}, bytesRead {}, bytes remaining {}",
        "[DFLog::RbxTransportRnaExpConnection] {}. receivePopMaxBytes. Channel {} not found",
    ])
    dump_streams()
    dump_flag_global("FailureFallbackToRbxTransport", "failureFallbackToRbxTransport")
    dump_flag_ptr("UseRbxTransportClient", "UseRbxTransportClient", n=2)
    dump_offset_xref_func("GetConnectionErrorName", "DisconnectAndroidAnticheatKick")


def _anchor_func(pattern, n=1, exact=False):
    s = find_str(pattern, exact)
    if s is None:
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if len(xs) < n:
        return None
    return func_of(xs[n - 1])


def _anchor_any(patterns, n=1):
    for p in patterns:
        f = _anchor_func(p, n, True)
        if f is None:
            f = _anchor_func(p, n, False)
        if f is not None:
            return f
    return None


def _slot_before(symbol, delta):
    for ea, nm in idautils.Names():
        if nm == symbol:
            return func_of(int(ida_bytes.get_qword(ea - delta)))
    return None


def _ops(ni):
    return [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]


def _mem_base_disp(op):
    if op.type == ida_ua.o_displ or op.type == ida_ua.o_phrase:
        return (0 if op.addr is None else op.addr, op.reg)
    return None


def _pe_fields():
    try:
        lf = int(ida_bytes.get_dword(BASE + 0x3C))
    except Exception:
        return (None, None)
    if lf <= 0 or lf >= MAX_EA:
        return (None, None)
    ts = sz = None
    try:
        ts = int(ida_bytes.get_dword(BASE + lf + 8))
        sz = int(ida_bytes.get_dword(BASE + lf + 80))
    except Exception:
        pass
    return (ts, sz)


def _vtable_slots(av):
    if av is None:
        return None
    n = 0
    while n < 128:
        try:
            ea = int(ida_bytes.get_qword(av + n * 8))
        except Exception:
            break
        if not _is_func_start(ea):
            break
        n += 1
    return n if n else None


def _disp_before_bt(fstart):
    lst = _insns(fstart)
    for i, (_, ni) in enumerate(lst):
        if ni.get_canon_mnem() != "bt":
            continue
        for k in range(i - 1, max(-1, i - 6), -1):
            n2 = lst[k][1]
            if n2.get_canon_mnem() != "mov":
                continue
            for op in _ops(n2):
                md = _mem_base_disp(op)
                if md is not None and md[0] > 0x40:
                    return md[0]
    return None


def _common_big_disp(funcs):
    from collections import Counter
    c = Counter()
    for f in funcs:
        if f is None:
            continue
        for _, ni in _insns(f):
            if ni.get_canon_mnem() != "mov":
                continue
            for op in _ops(ni):
                md = _mem_base_disp(op)
                if md is not None and md[0] > 0x100:
                    c[md[0]] += 1
    return c.most_common(1)[0][0] if c else None


def _small_cmp(fstart):
    from collections import Counter
    c = Counter()
    for _, ni in _insns(fstart):
        if ni.get_canon_mnem() != "cmp":
            continue
        oo = _ops(ni)
        if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_imm:
            v = oo[1].value & 0xFFFFFFFF
            if 1 <= v <= 64:
                c[v] += 1
    return c.most_common(1)[0][0] if c else None


def _lea_mem(fstart):
    for _, ni in _insns(fstart):
        if ni.get_canon_mnem() != "lea":
            continue
        for op in _ops(ni):
            md = _mem_base_disp(op)
            if md is not None and md[1] not in (4, 5) and 0x10 < md[0] < 0x100:
                return md[0]
    return None


def _cmp_mem_imm(fstart):
    for _, ni in _insns(fstart):
        if ni.get_canon_mnem() != "cmp":
            continue
        oo = _ops(ni)
        if not any(o.type == ida_ua.o_imm and (o.value & 0xFFFFFFFF) == 0 for o in oo):
            continue
        for op in oo:
            md = _mem_base_disp(op)
            if md is not None and md[1] not in (4, 5) and 0x10 < md[0] < 0x100:
                return md[0]
    return None


def _xref_funcs(pattern):
    s = find_str(pattern, exact=True)
    if s is None:
        s = find_str(pattern)
    if s is None:
        return []
    out = []
    for x in idautils.XrefsTo(s):
        f = func_of(x.frm)
        if f is not None and f not in out:
            out.append(f)
    return out


def _add_mem_imm(fstart):
    if fstart is None:
        return None
    for _, ni in _insns(fstart):
        if ni.get_canon_mnem() != "add":
            continue
        oo = _ops(ni)
        if len(oo) == 2 and oo[0].type == ida_ua.o_displ and oo[1].type == ida_ua.o_imm:
            v = oo[1].value & 0xFFFFFFFF
            if 0x10 <= v <= 0x400:
                return v
    return None


def _imul_imm(fstart):
    if fstart is None:
        return None
    for _, ni in _insns(fstart):
        if ni.get_canon_mnem() != "imul":
            continue
        for op in _ops(ni):
            if op.type == ida_ua.o_imm:
                v = op.value & 0xFFFFFFFF
                if 0x10 <= v <= 0x400:
                    return v
    return None


def _store_run_any(patterns):
    from collections import Counter
    c = Counter()
    for p in patterns:
        for f in _xref_funcs(p):
            v = _store_run_size(f)
            if v is not None:
                c[v] += 1
    return c.most_common(1)[0][0] if c else None


def _store_run_size(fstart):
    if fstart is None:
        return None
    by_base = {}
    for _, ni in _insns(fstart):
        if ni.get_canon_mnem() != "mov":
            continue
        oo = _ops(ni)
        if len(oo) != 2:
            continue
        md = _mem_base_disp(oo[0])
        if md is None:
            continue
        by_base.setdefault(md[1], set()).add(md[0])
    best = None
    best_arg = None
    for reg, ds in by_base.items():
        if 0 not in ds:
            continue
        run = [0]
        for d in sorted(ds):
            if d == run[-1] + 8:
                run.append(d)
            elif d > run[-1] + 8:
                break
        if len(run) >= 3:
            sz = run[-1] + 8
            if best is None or sz > best:
                best = sz
            if reg == 2 and (best_arg is None or sz > best_arg):
                best_arg = sz
    return best_arg if best_arg is not None else best


def dump_rbxtransport_layout():
    print("--- rbxtransportlayout ---")
    ts, sz = _pe_fields()
    print("ImageTimestamp = 0x%X" % ts if ts is not None else "ImageTimestamp: NO PE")
    print("ImageSize = 0x%X" % sz if sz is not None else "ImageSize: NO PE")
    avt = find_vtable("??_7RtcAppConnection@Impl@RbxTransport@RBX@@6B@")
    slots = _vtable_slots(avt)
    print("AppVtableSlots = 0x%X" % slots if slots is not None else "AppVtableSlots: NO VTABLE")
    csend = _anchor_func("Trying to send on a not ready channel!")
    crecv = _find_client_receive()
    cmask = _disp_before_bt(csend)
    print("ClientChannelMask = 0x%X" % cmask if cmask is not None else "ClientChannelMask: NO BT")
    capp = _common_big_disp((csend, crecv))
    print("ClientAppConnection = 0x%X" % capp if capp is not None else "ClientAppConnection: NO DISP")
    chc = _small_cmp(crecv)
    print("ChannelCount = 0x%X" % chc if chc is not None else "ChannelCount: NO CMP")
    cl = _anchor_func("RtcAppConnection::close", exact=True)
    app = None
    if cl is not None:
        for ea, tgt in scan_calls(cl):
            if _call_arg_lea_byte(ea, ("edx", "rdx", "dx"), 0x08, cl):
                app = tgt
                break
    sbytes = _lea_mem(app)
    sinline = _cmp_mem_imm(app)
    if sbytes is not None:
        print("StreamBytes = 0x%X" % sbytes)
        print("StreamLength = 0x%X" % (sbytes + 8))
    else:
        print("StreamBytes: NO LEA")
        print("StreamLength: NO LEA")
    if sinline is not None:
        print("StreamInlineMode = 0x%X" % sinline)
        print("StreamPrefix = 0x%X" % (sinline + 8))
    else:
        print("StreamInlineMode: NO CMP")
        print("StreamPrefix: NO CMP")
    ssz = _add_mem_imm(crecv)
    print("StreamSize = 0x%X" % ssz if ssz is not None else "StreamSize: NO ADD")
    armax = _anchor_any(["receivePopMaxBytes"])
    rss = _imul_imm(armax)
    print("ReceivedStreamSize = 0x%X" % rss if rss is not None else "ReceivedStreamSize: NO IMUL")
    rb = _store_run_any(["receivePop. Channel", "The state object field"])
    print("ReceiveBatchSize = 0x%X" % rb if rb is not None else "ReceiveBatchSize: NO RUN")
    sb = None
    for idx in (8, 9):
        if avt is None:
            break
        sf = _vtable_slot(avt, idx)
        if sf is None:
            continue
        arghits = []
        anyhits = []
        for _, tgt in scan_calls(sf):
            ba, best = _store_run_size_x(tgt)
            if ba is not None and 0x10 <= ba <= 0x40:
                arghits.append(ba)
            if best is not None and 0x10 <= best <= 0x40:
                anyhits.append(best)
        if arghits:
            sb = arghits[0]
            break
        if anyhits:
            sb = anyhits[0]
            break
    print("SendResultSize = 0x%X" % sb if sb is not None else "SendResultSize: NO RUN")


def dump_gcstep(name, fstart):
    if fstart is None:
        print("%s: NO HOST" % name)
        return None
    movsxd = False
    movaps = False
    for _, ni in _insns(fstart):
        m = ni.get_canon_mnem()
        if m == "movsxd":
            movsxd = True
        elif movsxd and m == "movaps":
            movaps = True
        elif movsxd and movaps and m == "call":
            for i in range(6):
                op = ni[i]
                if op.type == ida_ua.o_near:
                    print("%s = REBASE(0x%X)" % (name, op.addr - BASE))
                    return op.addr
            break
    print("%s: NO CALL" % name)
    return None


def dump_lea_after_movsxd(name, pattern):
    s = find_str(pattern, exact=True)
    if s is None:
        s = find_str(pattern)
    if s is None:
        print("%s: NO STRING" % name)
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        print("%s: NO XREF" % name)
        return None
    f = func_of(xs[0])
    if f is None:
        print("%s: xref not in func" % name)
        return None
    lst = _insns(f)
    idx = next((i for i, (a, _) in enumerate(lst) if a == xs[0]), None)
    if idx is None:
        print("%s: NO REF" % name)
        return None
    seen = False
    for i in range(idx, min(len(lst), idx + 40)):
        ni = lst[i][1]
        m = ni.get_canon_mnem()
        if m == "movsxd":
            seen = True
            continue
        if seen and m == "lea":
            ops = [ni[j] for j in range(6) if ni[j].type != ida_ua.o_void]
            if len(ops) == 2 and ops[1].type == ida_ua.o_mem:
                print("%s = REBASE(0x%X)" % (name, ops[1].addr - BASE))
                return ops[1].addr
            break
    print("%s: NO LEA" % name)
    return None


def dump_metatable_locked():
    s = find_str("The metatable is locked", exact=True)
    if s is None:
        s = find_str("The metatable is locked")
    if s is None:
        print("LuaPushString: NO STRING")
        print("LuaSetField: NO STRING")
        return
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        print("LuaPushString: NO XREF")
        print("LuaSetField: NO XREF")
        return
    f = func_of(xs[0])
    if f is None:
        print("LuaPushString: NOFUNC")
        print("LuaSetField: NOFUNC")
        return
    lst = _insns(f)
    idx = next((i for i, (a, _) in enumerate(lst) if a == xs[0]), None)
    push = None
    setf = None
    for i in range((idx or 0) + 1, len(lst)):
        ni = lst[i][1]
        m = ni.get_canon_mnem()
        if m == "call" and push is None:
            ops = [ni[j] for j in range(6) if ni[j].type != ida_ua.o_void]
            if ops and ops[0].type == ida_ua.o_near:
                push = ops[0].addr
        elif m == "jmp" and setf is None:
            ops = [ni[j] for j in range(6) if ni[j].type != ida_ua.o_void]
            if ops:
                if ops[0].type == ida_ua.o_near:
                    setf = ops[0].addr
                elif ops[0].type == ida_ua.o_imm:
                    setf = ops[0].value & 0xFFFFFFFFFFFFFFFF
        if push is not None and setf is not None:
            break
    if push is not None:
        print("LuaPushString = REBASE(0x%X)" % (push - BASE))
    else:
        print("LuaPushString: NO CALL")
    if setf is not None:
        print("LuaSetField = REBASE(0x%X)" % (setf - BASE))
    else:
        print("LuaSetField: NO JMP")


def dump_castargs():
    s = find_str("Argument %d missing or nil", exact=True)
    if s is None:
        s = find_str("Argument %d missing or nil")
    if s is None:
        print("CastArgs: NO STRING")
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if len(xs) < 2:
        print("CastArgs: only %d xrefs" % len(xs))
        return None
    f = func_of(xs[1])
    if f is None:
        print("CastArgs: xref not in func")
        return None
    lst = _insns(f)
    pick = None
    for i, (a, ni) in enumerate(lst):
        if ni.get_canon_mnem() != "call":
            continue
        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
        if not oo or oo[0].type != ida_ua.o_near:
            continue
        hit = False
        for k in range(max(0, i - 12), i):
            m = lst[k][1].get_canon_mnem()
            o2 = [lst[k][1][t] for t in range(6) if lst[k][1][t].type != ida_ua.o_void]
            if (m == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg
                    and _reg_name(o2[0].reg) in ("r9d", "r9")
                    and o2[1].type == ida_ua.o_imm
                    and (o2[1].value & 0xFFFFFFFFFFFFFFFF) == 1):
                hit = True
                break
        if hit:
            pick = oo[0].addr
            break
    if pick is None:
        pick = first_call_in(f)
    if pick is None:
        print("CastArgs: NO CALL")
        return None
    print("CastArgs = REBASE(0x%X)" % (pick - BASE))
    return pick


def _next_call(start, limit):
    ea = start
    end = start + limit
    while ea < end and ea < MAX_EA:
        ni = ida_ua.insn_t()
        if not ida_ua.decode_insn(ni, ea):
            ea += 1
            continue
        if ni.get_canon_mnem() == "call":
            for i in range(6):
                op = ni[i]
                if op.type == ida_ua.o_near:
                    return op.addr
        ea += ni.size if ni.size else 1
    return None


def _resolved_value(name):
    pre = name + " = REBASE(0x"
    for line in _LINES:
        if line.startswith(pre):
            try:
                return int(line[len(pre):-1], 16) + BASE
            except ValueError:
                return None
    return None


def _xref_count(ea):
    try:
        return sum(1 for x in idautils.XrefsTo(ea) if x.iscode)
    except Exception:
        return 0


def _lua_region():
    vals = [_resolved_value(n) for n in ("LuauExecute", "LuaGRunError", "RunError")]
    vals = [v for v in vals if v]
    if not vals:
        return None
    lo = min(vals) - 0x20000
    hi = max(vals) + 0x20000
    if hi - lo > 0x800000:
        return None
    return (lo, hi)


def _gc_step_host(fstart):
    state = 0
    for _, ni in _insns(fstart):
        m = ni.get_canon_mnem()
        if state == 0 and m == "movsxd":
            state = 1
        elif state == 1 and m == "movaps":
            state = 2
        elif state == 2 and m == "call":
            oo = _ops(ni)
            if oo and oo[0].type == ida_ua.o_near:
                return oo[0].addr
            return None
    return None


def _scan_luac_step():
    reg = _lua_region()
    if reg is None:
        return None
    best = None
    for f in idautils.Functions(reg[0], reg[1]):
        fn = ida_funcs.get_func(f)
        if fn is None:
            continue
        sz = fn.end_ea - fn.start_ea
        if sz < 0x100 or sz > 0x800:
            continue
        nrefs = _xref_count(fn.start_ea)
        if nrefs < 15:
            continue
        tgt = _gc_step_host(fn.start_ea)
        if tgt is None:
            continue
        tf = ida_funcs.get_func(tgt)
        if tf is None or (tf.end_ea - tf.start_ea) < 0x80:
            continue
        if _xref_count(tgt) > 12:
            continue
        repeats = len([1 for _, t in scan_calls(fn.start_ea) if t == tgt])
        score = nrefs + (100 if repeats > 1 else 0)
        if best is None or score > best[0]:
            best = (score, fn.start_ea)
    return best[1] if best else None


def dump_luac_step():
    s = find_str("Attempt to load a function from a different Lua VM", exact=True)
    if s is None:
        s = find_str("Attempt to load a function from a different Lua VM")
    if s is None:
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        return None
    first = _next_call(xs[0], 0x100)
    if first is None:
        return None
    second = _next_call(first, 0x100)
    if second is None or _gc_step_host(second) is None:
        return None
    return second


def dump_luadthrow():
    s = find_str("resulting string too large", exact=True)
    if s is None:
        s = find_str("resulting string too large")
    if s is None:
        print("LuaDThrow: NO STRING")
        return None
    throw_syms = set()
    for sym in ("__CxxThrowException", "_CxxThrowException"):
        for ea, nm in idautils.Names():
            if nm == sym:
                throw_syms.add(ea)
    votes = {}
    for x in idautils.XrefsTo(s):
        f = func_of(x.frm)
        if f is None:
            continue
        lst = _insns(f)
        for i, (a, ni) in enumerate(lst):
            if ni.get_canon_mnem() != "call":
                continue
            oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
            if not oo or oo[0].type != ida_ua.o_near:
                continue
            immok = False
            for k in range(max(0, i - 6), i):
                m2 = lst[k][1].get_canon_mnem()
                o2 = [lst[k][1][t] for t in range(6) if lst[k][1][t].type != ida_ua.o_void]
                if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 2 and o2[1].type == ida_ua.o_imm and 0 <= (o2[1].value & 0xFFFFFFFF) <= 8:
                    immok = True
                    break
            if not immok:
                continue
            tgt = oo[0].addr
            tf = ida_funcs.get_func(tgt)
            if tf is None:
                continue
            throws = False
            for h in idautils.Heads(tf.start_ea, tf.end_ea):
                nj = ida_ua.insn_t()
                if not ida_ua.decode_insn(nj, h):
                    continue
                if nj.get_canon_mnem() != "call":
                    continue
                for t in range(6):
                    op = nj[t]
                    if op.type == ida_ua.o_near and op.addr in throw_syms:
                        throws = True
                        break
                if throws:
                    break
            if throws:
                votes[tgt] = votes.get(tgt, 0) + 1
    if not votes:
        print("LuaDThrow: NO THROW")
        return None
    best = max(votes, key=lambda k: votes[k])
    print("LuaDThrow = REBASE(0x%X)" % (best - BASE))
    return best


def dump_luau_extras():
    print("--- luau ---")
    lcs = _scan_luac_step()
    if lcs is None:
        lcs = dump_luac_step()
    if lcs is not None:
        print("LuaCStep = REBASE(0x%X)" % (lcs - BASE))
    else:
        print("LuaCStep: NO CHAIN")
    dump_gcstep("GcStep", lcs)
    dump_luadthrow()
    dump_lea_after_movsxd("LuaTTypeNames", "no value")
    dump_metatable_locked()
    dump_castargs()


def _resolved(name):
    pre = name + " = REBASE("
    return any(line.startswith(pre) for line in _LINES)


def _smallest_caller(symbols):
    for sym in symbols:
        for ea, nm in idautils.Names():
            if nm != sym:
                continue
            best = None
            for x in idautils.XrefsTo(ea):
                f = ida_funcs.get_func(x.frm)
                if f is None:
                    continue
                sz = f.end_ea - f.start_ea
                if best is None or sz < best[0]:
                    best = (sz, f.start_ea)
            if best is not None:
                return best[1]
    return None


def dump_opcode_table():
    it = find_str("iterate over", exact=True)
    if it is None:
        it = find_str("iterate over")
    if it is not None:
        votes = {}
        for x in idautils.XrefsTo(it):
            f = func_of(x.frm)
            if f is None:
                continue
            lst = _insns(f)
            for i, (a, ni) in enumerate(lst):
                if ni.get_canon_mnem() != "call":
                    continue
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if not oo or oo[0].type != ida_ua.o_near:
                    continue
                mem = None
                imm = None
                for k in range(max(0, i - 10), i):
                    m2 = lst[k][1].get_canon_mnem()
                    o2 = [lst[k][1][t] for t in range(6) if lst[k][1][t].type != ida_ua.o_void]
                    if m2 == "lea" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 1 and o2[1].type == ida_ua.o_mem and o2[1].addr != it and _seg_name(o2[1].addr) != ".text":
                        mem = o2[1].addr
                    if m2 == "mov" and len(o2) == 2 and o2[0].type == ida_ua.o_reg and o2[0].reg == 2 and o2[1].type == ida_ua.o_imm and 0 < (o2[1].value & 0xFFFFFFFF) < 300:
                        imm = o2[1].value & 0xFFFFFFFF
                if mem is not None and imm is not None:
                    votes.setdefault(mem, set()).add(imm)
        best = None
        bestn = 0
        for mem, ims in votes.items():
            if len(ims) >= 3 and len(ims) > bestn:
                bestn = len(ims)
                best = mem
        if best is not None:
            print("OpcodeLookUpTable = REBASE(0x%X)" % (best - BASE))
            return best
    anchor = None
    for mn in ("FALLBACK_NAMECALL", "NEWCLOSURE", "DUPCLOSURE", "LOAD_TAG", "STORE_TAG"):
        s = find_str(mn, exact=True)
        if s is not None:
            anchor = s
            break
    if anchor is None:
        return None
    pool = None
    for x in idautils.XrefsTo(anchor):
        f = ida_funcs.get_func(x.frm)
        if f is None:
            continue
        for _, ni in _insns(f.start_ea):
            if ni.get_canon_mnem() != "lea":
                continue
            oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
            if len(oo) == 2 and oo[1].type == ida_ua.o_mem and abs(oo[1].addr - anchor) < 0x4000:
                if pool is None or oo[1].addr < pool:
                    pool = oo[1].addr
    if pool is None:
        return None
    print("OpcodeLookUpTable = REBASE(0x%X)" % (pool - BASE))
    return pool


def dump_lua_d_throw():
    t = _lua_throw_target()
    if t is None:
        print("LuaDThrow: NO THROW")
        return None
    print("LuaDThrow = REBASE(0x%X)" % (t - BASE))
    return t


def _lua_throw_target():
    reg = _lua_region()
    best = None
    for sym in ("__CxxThrowException", "_CxxThrowException"):
        for ea, nm in idautils.Names():
            if nm != sym:
                continue
            for x in idautils.XrefsTo(ea):
                f = ida_funcs.get_func(x.frm)
                if f is None:
                    continue
                if reg is not None and not (reg[0] <= f.start_ea <= reg[1]):
                    continue
                sz = f.end_ea - f.start_ea
                if best is None or sz < best[0]:
                    best = (sz, f.start_ea)
    if best is not None:
        return best[1]
    return _smallest_caller(("__CxxThrowException", "_CxxThrowException"))


def dump_lua_g_runerror():
    s = find_str("collectgarbage must be called with 'count'", exact=True)
    if s is None:
        s = find_str("collectgarbage must be called with 'count'")
    if s is None:
        print("LuaGRunError: NO STRING")
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        print("LuaGRunError: NO XREF")
        return None
    reg = _lua_region()
    cands = []
    for x in xs:
        t = _next_call(x, 0x40)
        if t is None:
            continue
        if reg is not None and not (reg[0] <= t <= reg[1]):
            continue
        cands.append(t)
    if not cands:
        cands = [t for t in (_next_call(x, 0x40) for x in xs) if t is not None]
    if not cands:
        print("LuaGRunError: NO CHAIN")
        return None
    print("LuaGRunError = REBASE(0x%X)" % (cands[0] - BASE))
    return cands[0]


def dump_lua_opushfstring():
    f = _smallest_caller(("_stdio_common_vsprintf", "__stdio_common_vsprintf"))
    if f is None:
        print("LuaOPushFString: NO CORE")
        return None
    print("LuaOPushFString = REBASE(0x%X)" % (f - BASE))
    return f


def dump_luau_execute():
    s = find_str("iterate over", exact=True)
    if s is None:
        s = find_str("iterate over")
    if s is None:
        print("LuauExecute: NO STRING")
        return None
    c = {}
    for x in idautils.XrefsTo(s):
        f = func_of(x.frm)
        if f is not None:
            c[f] = c.get(f, 0) + 1
    if not c:
        print("LuauExecute: NO XREF")
        return None
    best = max(c, key=lambda k: c[k])
    print("LuauExecute = REBASE(0x%X)" % (best - BASE))
    return best


NATIVE_STRING_ANCHORS = {
    "NativeDestroyString": "doNotFallbackToBaselineRepresentation",
    "NativeVerify": "bytecode type version mismatch",
}
_VERIFY_FLAG_RE = (r"\*\s*\(\s*_\w+\s*\*\s*\)\s*\(\s*\*\s*\(\s*_\w+\s*\*\s*\)\s*\([^()]*\)"
                   r"\s*\+\s*(0x[0-9A-Fa-f]+|\d+)\s*LL?\s*\)\s*&\s*=")
_VERSION_TABLE_MARK = "LibMP"


def _str_xref_funcs(needle):
    out = []
    for s in idautils.Strings():
        if needle in str(s):
            for x in idautils.XrefsTo(s.ea, 0):
                f = ida_funcs.get_func(x.frm)
                if f and f.start_ea not in out:
                    out.append(f.start_ea)
    return out


def _call_counts(fstart):
    counts = {}
    for ea in idautils.FuncItems(fstart):
        if idc.print_insn_mnem(ea) != "call":
            continue
        tgt = idc.get_operand_value(ea, 0)
        g = ida_funcs.get_func(tgt)
        if g:
            counts[g.start_ea] = counts.get(g.start_ea, 0) + 1
    return counts


def _find_destroystring():
    sets = []
    for f0 in _str_xref_funcs(NATIVE_STRING_ANCHORS["NativeDestroyString"]):
        sets.append({c for c, n in _call_counts(f0).items() if n >= 8})
    if not sets:
        return None
    common = set.intersection(*sets)
    if not common:
        return None
    best = None
    for f0 in _str_xref_funcs(NATIVE_STRING_ANCHORS["NativeDestroyString"]):
        for c, n in _call_counts(f0).items():
            if c in common and (best is None or n > best[1]):
                best = (c, n)
    return best


def _find_verify():
    for f0 in _str_xref_funcs(NATIVE_STRING_ANCHORS["NativeVerify"]):
        try:
            txt = str(ida_hexrays.decompile(f0))
        except Exception:
            continue
        for m in re.finditer(r"\(\s*unsigned int\)\s*(sub_[0-9A-Fa-f]+)\s*\(([^;]*?)\)\s*!=\s*1\s*\)", txt):
            nm = idc.get_name_ea_simple(m.group(1))
            g = ida_funcs.get_func(nm)
            if g:
                return g.start_ea
    return None


def _find_key(verify):
    if verify is None:
        return None
    for callee in _call_counts(verify):
        try:
            txt = str(ida_hexrays.decompile(callee))
        except Exception:
            continue
        if "unk_" not in txt:
            continue
        for m in re.finditer(r"&(unk_[0-9A-Fa-f]+)", txt):
            e = idc.get_name_ea_simple(m.group(1))
            if e == idc.BADADDR:
                continue
            blob = ida_bytes.get_bytes(e, 64) or b""
            if _VERSION_TABLE_MARK.encode() in blob:
                return callee
    return None



IDENTITY_ANCHOR = "may only be instantiated by CoreScripts"
_TLS_RESOLVE_RE = r"(sub_[0-9A-Fa-f]+)\(\s*(?:\(a1:\s*)?(qword_[0-9A-Fa-f]+)\s*\)"


def _find_identity():
    for f0 in _str_xref_funcs(IDENTITY_ANCHOR):
        try:
            txt = str(ida_hexrays.decompile(f0))
        except Exception:
            continue
        for m in re.finditer(_TLS_RESOLVE_RE, txt):
            res = idc.get_name_ea_simple(m.group(1))
            ptr = idc.get_name_ea_simple(m.group(2))
            if res == idc.BADADDR or ptr == idc.BADADDR:
                continue
            if ida_funcs.get_func(res) is not None and ida_funcs.get_func(ptr) is None:
                return res, ptr
    return None, None


def dump_identity():
    res, ptr = _find_identity()
    if res is None:
        print("IdentityPtr: NO TLS RESOLVE")
        return
    print("IdentityPtr = REBASE(0x%X)" % (ptr - BASE))
    print("GetTlsPointer = REBASE(0x%X)" % (res - BASE))


def dump_natives():
    print("--- native ---")
    ds = _find_destroystring()
    if ds:
        print("NativeDestroyString = REBASE(0x%X)" % (ds[0] - BASE))
        print("NativeDestroyStringRepeatedIn = %d" % ds[1])
    else:
        print("NativeDestroyString: NO TAIL CALLEE")
    vf = _find_verify()
    if vf:
        print("NativeVerify = REBASE(0x%X)" % (vf - BASE))
        try:
            vtxt = str(ida_hexrays.decompile(vf))
        except Exception:
            vtxt = ""
        m = re.search(_VERIFY_FLAG_RE, vtxt)
        if m:
            print("NativeVerifyFlagOffset = 0x%X" % int(m.group(1), 0))
        else:
            print("NativeVerifyFlagOffset: NO SHAPE")
        key = _find_key(vf)
        if key:
            print("NativeKey = REBASE(0x%X)" % (key - BASE))
        else:
            print("NativeKey: NO TABLE CALLEE")
    else:
        print("NativeVerify: NO NE1 CALLEE")


def dump_luau_core():
    print("--- luau ---")
    if not _resolved("LuaGRunError"):
        dump_lua_g_runerror()
    if not _resolved("LuaDThrow"):
        dump_lua_d_throw()
    if not _resolved("LuaOPushFString"):
        dump_lua_opushfstring()
    if not _resolved("LuauExecute"):
        dump_luau_execute()
    dump_natives()


def dump_remote():
    print("--- remoteevent ---")
    dump_func("FireServer", "FireServer can only be called from the client")
    dump_func("FireClient", "FireClient can only be called from the server")
    dump_func("FireAllClients", "FireAllClients can only be called from the server")
    dump_func("InvokeServer", "InvokeServer can only be called from the client")
    dump_func("InvokeClient", "InvokeClient can only be called from the server")


def dump_sky():
    print("--- sky ---")
    dump_func("DrawCubeCall", "AdvSkyVS")
    dump_func("DrawSkyPixel", "AdvSkyFS")
    dump_func("DrawSkyEnv", "AdvSkyEnvFS")
    dump_func("DrawSun", "AdvSunFS")
    dump_func("DrawStars", "AdvStarsFS")
    dump_func("SkyThread", "AdvSkyThread")
    dump_func("CubeTextures", "textures/sky/sky512_dn.tex")
    dump_flag_ptr("SkyGroup", "RenderAdvSkyGroup")


def _raknet_wrapper_funcs(lo, hi):
    out = []
    for f in idautils.Functions(lo, hi):
        fn = ida_funcs.get_func(f)
        if fn is None:
            continue
        sz = fn.end_ea - fn.start_ea
        if sz < 0x80 or sz > 0x600:
            continue
        r848 = set()
        r264 = set()
        for h in idautils.Heads(fn.start_ea, fn.end_ea):
            ni = ida_ua.insn_t()
            if not ida_ua.decode_insn(ni, h):
                continue
            for t in range(6):
                op = ni[t]
                if op.type == ida_ua.o_displ and op.addr == 848:
                    r848.add(op.reg)
                if op.type == ida_ua.o_displ and op.addr == 264:
                    r264.add(op.reg)
            if r848 & r264:
                break
        if r848 & r264:
            out.append(f)
    return out


def _calls_getfflag(fstart, gff):
    if gff is None:
        return False
    for _, tgt in scan_calls(fstart):
        if tgt == gff:
            return True
    return False


def _raknet_send_via_wrappers():
    sps = None
    ss = find_str("SendPacketsToSelfToUnblockSocketReceiveT")
    if ss is not None:
        for x in sorted(x.frm for x in idautils.XrefsTo(ss)):
            f = func_of(x)
            if f is not None:
                sps = f
                break
    if sps is None:
        return None
    wraps = _raknet_wrapper_funcs(sps - 0x8000, sps + 0x8000)
    if not wraps:
        return None
    votes = {}
    for w in wraps:
        for _, tgt in scan_calls(w):
            votes[tgt] = votes.get(tgt, 0) + 1
    need = 2 if len(wraps) >= 2 else 1
    gff = _resolved_value("GetFFlag")
    cands = []
    for tgt, n in votes.items():
        if n < need:
            continue
        tf = ida_funcs.get_func(tgt)
        if tf is None:
            continue
        sz = tf.end_ea - tf.start_ea
        if 0x250 <= sz <= 0x500:
            cands.append(tgt)
    if not cands:
        return None
    if gff is not None:
        gf = [t for t in cands if _calls_getfflag(t, gff)]
        if len(gf) == 1:
            return gf[0]
        return None
    if len(cands) == 1:
        return cands[0]
    best = max(cands, key=lambda t: votes[t])
    if sum(1 for t in cands if votes[t] == votes[best]) == 1:
        return best
    return None


def _raknet_send_via_disconnect():
    ds = find_str("Sending disconnect")
    if ds is None:
        return (None, None)
    for x in sorted(x.frm for x in idautils.XrefsTo(ds)):
        df = func_of(x)
        if df is None:
            continue
        big = []
        for _, tgt in scan_calls(df):
            tf = ida_funcs.get_func(tgt)
            if tf is not None and (tf.end_ea - tf.start_ea) >= 0x200:
                if tgt not in big:
                    big.append(tgt)
        if len(big) >= 2:
            big.sort(key=lambda t: ida_funcs.get_func(t).end_ea - ida_funcs.get_func(t).start_ea, reverse=True)
            b0, b1 = big[0], big[1]
            c0 = sum(1 for _ in idautils.XrefsTo(b0))
            c1 = sum(1 for _ in idautils.XrefsTo(b1))
            z0 = ida_funcs.get_func(b0).end_ea - ida_funcs.get_func(b0).start_ea
            z1 = ida_funcs.get_func(b1).end_ea - ida_funcs.get_func(b1).start_ea
            if (c0 < c1 and z0 < z1) or (c1 < c0 and z1 < z0):
                sendf = b0 if (c0 < c1) else b1
                xfunc = b1 if (c0 < c1) else b0
                return (sendf, xfunc)
    return (None, None)


def _raknet_rls_via_string():
    txs = find_str("raknet/tx-outgoing", exact=True)
    if txs is None:
        txs = find_str("raknet/tx-outgoing")
    if txs is None:
        return None
    for x in sorted(x.frm for x in idautils.XrefsTo(txs)):
        tf = func_of(x)
        if tf is None:
            continue
        fn = ida_funcs.get_func(tf)
        if fn is not None and (fn.end_ea - fn.start_ea) >= 0x100:
            return tf
    return None


def _raknet_rls_via_pair(xfunc):
    if xfunc is None:
        return None
    cand = []
    for _, tgt in scan_calls(xfunc):
        tf = ida_funcs.get_func(tgt)
        if tf is not None and 0x200 <= (tf.end_ea - tf.start_ea) <= 0x800:
            cand.append(tgt)
    if not cand:
        return None
    top = max(cand, key=lambda t: ida_funcs.get_func(t).end_ea - ida_funcs.get_func(t).start_ea)
    if sum(1 for _ in idautils.XrefsTo(top)) <= 3:
        return top
    return None


def dump_raknet():
    print("--- raknet ---")
    dump_func("Receive", "Incoming packet error")
    dump_func("ReportNetworkError", "ConnectionFailure", exact=True)
    dump_func("HandleConnectionState", "updateServerConnectionState")
    s2, x2 = _raknet_send_via_disconnect()
    sendf = s2
    if sendf is None:
        sendf = _raknet_send_via_wrappers()
    rls = _raknet_rls_via_string()
    if rls is None and x2 is not None:
        rls = _raknet_rls_via_pair(x2)
    if sendf is not None:
        print("Send = REBASE(0x%X)" % (sendf - BASE))
    else:
        print("Send: NO SEND")
    if rls is not None:
        print("ReliabilityLayerSend = REBASE(0x%X)" % (rls - BASE))
    else:
        print("ReliabilityLayerSend: NO RLS")
    dump_func("ProcessNetworkPacket", "RakPeer::ProcessNetworkPacket", exact=True)
    if dump_func("UpdateNetworkLoop", "Timed-out: Failed to gracefully end update loop") is None:
        dump_func("UpdateNetworkLoop", "[DFLog::RakNetPktTrace]")
    dump_func("SendPacketsToSelf", "SendPacketsToSelfToUnblockSocketReceiveT")
    dump_func("RakPeerReceive", "RakNet Receiving")
    vt = find_vtable("??_7RakPeer@RakNet@@6B@")
    if vt is not None:
        print("RakPeerVirtualTable = REBASE(0x%X)" % (vt - BASE))
    dump_func("ConvertItemEnumToString", "Stream Prefetch Request Items")

def _fflag_wrappers(patterns):
    out = []
    for pat in patterns:
        s = find_str(pat, exact=True)
        if s is None:
            s = find_str(pat)
        if s is None:
            continue
        for x in idautils.XrefsTo(s):
            f = func_of(x.frm)
            if f is None:
                continue
            fn = ida_funcs.get_func(f)
            if fn is None or (fn.end_ea - fn.start_ea) > 0x100:
                continue
            out.append((f, s, x.frm))
    return out


def _call_after_lea_r8(fstart, str_ea):
    lst = _insns(fstart)
    for i, (a, ni) in enumerate(lst):
        if ni.get_canon_mnem() != "lea":
            continue
        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
        if len(oo) != 2 or oo[0].type != ida_ua.o_reg or oo[0].reg != 8:
            continue
        if oo[1].type != ida_ua.o_mem or oo[1].addr == str_ea:
            continue
        if _seg_name(oo[1].addr) == ".text":
            continue
        for j in range(i + 1, min(len(lst), i + 7)):
            nj = lst[j][1]
            if nj.get_canon_mnem() != "call":
                continue
            oo2 = [nj[t] for t in range(6) if nj[t].type != ida_ua.o_void]
            if oo2 and oo2[0].type == ida_ua.o_near:
                return oo2[0].addr
    return None


def _bank_in_wrapper(fstart):
    import ida_segment
    dseg = ida_segment.get_segm_by_name(".data")
    if dseg is None:
        return None
    q0, q1 = int(dseg.start_ea), int(dseg.end_ea)
    for _, ni in _insns(fstart):
        if ni.get_canon_mnem() != "mov":
            continue
        oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
        if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_mem and q0 <= oo[1].addr < q1:
            return oo[1].addr
    return None


def _func_refs_addr(fstart, addr):
    f = ida_funcs.get_func(fstart)
    if f is None:
        return False
    for h in idautils.Heads(f.start_ea, f.end_ea):
        ni = ida_ua.insn_t()
        if not ida_ua.decode_insn(ni, h):
            continue
        for t in range(6):
            op = ni[t]
            if op.type == ida_ua.o_mem and op.addr == addr:
                return True
    return False


def dump_func_last(name, pattern, n=2, exact=False):
    s = find_str(pattern, exact)
    if not s:
        print("%s: NO STRING" % name)
        return None
    xs = sorted(x.frm for x in idautils.XrefsTo(s))
    if not xs:
        print("%s: NO XREF" % name)
        return None
    pick = xs[n - 1] if len(xs) >= n else xs[-1]
    f = func_of(pick)
    if f is None:
        print("%s: xref 0x%x not in func" % (name, pick))
        return None
    print("%s = REBASE(0x%X)" % (name, f - BASE))
    return f


def _find_client_receive():
    vt = find_vtable("??_7RbxTransportConnection@NetworkBase@RBX@@6B@")
    if vt is None:
        return None
    for n in range(48):
        try:
            ea = int(ida_bytes.get_qword(vt + n * 8))
        except Exception:
            continue
        if not _is_func_start(ea):
            continue
        f = ida_funcs.get_func(ea)
        sz = f.end_ea - f.start_ea
        if sz < 0x100 or sz > 0x600:
            continue
        cmps = {}
        adds = 0
        for _, ni in _insns(ea):
            m = ni.get_canon_mnem()
            if m == "cmp":
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_imm:
                    v = oo[1].value & 0xFFFFFFFF
                    if 2 <= v <= 64:
                        cmps[v] = cmps.get(v, 0) + 1
            elif m == "add":
                oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                if len(oo) == 2 and oo[0].type == ida_ua.o_displ and oo[1].type == ida_ua.o_imm:
                    v = oo[1].value & 0xFFFFFFFF
                    if 0x10 <= v <= 0x400:
                        adds += 1
        if adds >= 1 and any(v >= 2 for v in cmps.values()):
            return ea
    return None


def _store_run_size_x(fstart):
    if fstart is None:
        return (None, None)
    by_base = {}
    for _, ni in _insns(fstart):
        m = ni.get_canon_mnem()
        if m not in ("mov", "movups", "movdqu"):
            continue
        oo = _ops(ni)
        if len(oo) != 2:
            continue
        md = _mem_base_disp(oo[0])
        if md is None:
            continue
        d, reg = md
        by_base.setdefault(reg, set()).add(d)
        if m in ("movups", "movdqu"):
            by_base[reg].add(d + 8)
    best = None
    best_arg = None
    for reg, ds in by_base.items():
        if 0 not in ds:
            continue
        run = [0]
        for d in sorted(ds):
            if d == run[-1] + 8:
                run.append(d)
            elif d > run[-1] + 8:
                break
        if len(run) >= 3:
            sz = run[-1] + 8
            if best is None or sz > best:
                best = sz
            if reg == 2 and (best_arg is None or sz > best_arg):
                best_arg = sz
    return (best_arg, best)


def dump_misc():
    import ida_segment
    print("--- misc ---")
    pi = None
    ps = find_str("Current identity is %d", exact=True)
    if ps is not None:
        pxs = sorted(x.frm for x in idautils.XrefsTo(ps))
        if pxs:
            pf2 = ida_funcs.get_func(pxs[0])
            if pf2 is not None:
                pi = pf2.start_ea
    if pi is not None:
        print("PrintIdentity = REBASE(0x%X)" % (pi - BASE))
    else:
        print("PrintIdentity: NO STRING")
    gff = None
    bank = None
    flag_pats = ["DebugWinDisableUpdates", "UseRbxTransportClient", "RenderAdvSkyGroup",
                 "LockViolationInstanceCrash", "LockViolationScriptCrash", "EnableLoadModule",
                 "failureFallbackToRbxTransport"]
    gv = {}
    bv = {}
    for fstart, s, ref in _fflag_wrappers(flag_pats):
        t = _call_after_lea_r8(fstart, s)
        if t is not None:
            gv[t] = gv.get(t, 0) + 1
        b = _bank_in_wrapper(fstart)
        if b is not None:
            bv[b] = bv.get(b, 0) + 1
    if gv:
        gff = max(gv, key=lambda k: gv[k])
    if bv:
        bank = max(bv, key=lambda k: bv[k])
    if gff is not None:
        print("GetFFlag = REBASE(0x%X)" % (gff - BASE))
    else:
        print("GetFFlag: NO VOTE")
    if bank is not None:
        print("FFlagPointer = REBASE(0x%X)" % (bank - BASE))
    else:
        print("FFlagPointer: NO VOTE")
    dump_flag_ptr("EnableLoadModule", "EnableLoadModule")
    sf = None
    s1 = find_str("[FLog::FastLogValueChanged] Setting variable {}", exact=True)
    s2 = find_str("[FLog::FastLogValueChanged] ...(previously unknown)...", exact=True)
    if s1 is not None and s2 is not None:
        x1 = sorted(x.frm for x in idautils.XrefsTo(s1))
        x2 = sorted(x.frm for x in idautils.XrefsTo(s2))
        if x1 and x2:
            f1 = ida_funcs.get_func(x1[0])
            if f1 is not None:
                for x in x2:
                    wf = ida_funcs.get_func(x)
                    if wf is not None and wf.start_ea == f1.start_ea:
                        sf = f1.start_ea
                        break
    if sf is not None:
        print("SetFFlag = REBASE(0x%X)" % (sf - BASE))
    else:
        print("SetFFlag: NO PAIR")
    bt = find_vtable("??_7?$ValueGetSet@_N@FLog@@6B@")
    if bt is not None:
        print("BooleanType = REBASE(0x%X)" % (bt - BASE))
    dump_flag_ptr("LockViolationInstanceCrash", "LockViolationInstanceCrash")
    dump_flag_ptr("LockViolationScriptCrash", "LockViolationScriptCrash")


_NS_NAMES = {
    "task": "Task",
    "instance": "Instance",
    "coroutine": "Coroutine",
    "luab": "LuaB",
    "lua": "Luau",
    "lual": "LuaL",
    "luau": "Luau",
    "scriptcontext": "ScriptContext",
    "Capabilities": "Capability",
    "classdescriptor": "ClassDescriptor",
    "engine misc": "EngineMisc",
    "taskscheduler": "TaskScheduler",
    "raycast": "Raycast",
    "rbxtransport": "RbxTransport",
    "rbxtransportlayout": "RbxTransport",
    "raknet": "RakNet",
    "remoteevent": "RemoteEvent",
    "sky": "Sky",
    "misc": "Misc",
    "global": "Global",
    "vftables": "VTable",
}


_TYPE_BY_NAME = {
    "ImageTimestamp": "std::size_t",
    "ImageSize": "std::size_t",
    "AppVtableSlots": "std::size_t",
    "ChannelCount": "std::size_t",
    "ClientAppConnection": "std::size_t",
    "ClientChannelMask": "std::size_t",
    "StreamBytes": "std::size_t",
    "StreamLength": "std::size_t",
    "StreamInlineMode": "std::size_t",
    "StreamPrefix": "std::size_t",
    "StreamSize": "std::size_t",
    "ReceivedStreamSize": "std::size_t",
    "ReceiveBatchSize": "std::size_t",
    "SendResultSize": "std::size_t",
}


def _hpp_type(nsn, name):
    return _TYPE_BY_NAME.get(name, "std::size_t")


_NO_REBASE = set(_TYPE_BY_NAME) | {"RequireBypass", "CapabilityStruct", "NativeVerifyFlagOffset"}


_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(\.\d+)?$")


def _string_at(ea):
    if ea is None or ea == 0 or ea >= MAX_EA:
        return None
    raw = None
    try:
        raw = idc.get_strlit_contents(ea)
    except Exception:
        raw = None
    if not raw:
        try:
            raw = ida_bytes.get_strlit_contents(ea, -1, 0)
        except Exception:
            raw = None
    if not raw:
        return None
    try:
        t = raw.decode()
    except UnicodeDecodeError:
        return None
    return t if _VERSION_RE.match(t) else None


def _read_version_at(addr):
    v = _string_at(addr)
    if v:
        return v
    try:
        p = int(ida_bytes.get_qword(addr))
    except Exception:
        return None
    return _string_at(p)


def _version_string():
    s = find_str("AppVersion", exact=True)
    if s is None:
        s = find_str("AppVersion")
    if s is not None:
        xs = sorted(x.frm for x in idautils.XrefsTo(s))
        if xs:
            f = func_of(xs[1] if len(xs) >= 2 else xs[0])
            if f is not None:
                for _, ni in _insns(f):
                    if ni.get_canon_mnem() not in ("lea", "mov"):
                        continue
                    oo = [ni[t] for t in range(6) if ni[t].type != ida_ua.o_void]
                    if len(oo) == 2 and oo[0].type == ida_ua.o_reg and oo[1].type == ida_ua.o_mem:
                        v = _read_version_at(oo[1].addr)
                        if v:
                            return v
    import ida_strlist
    qty = ida_strlist.get_strlist_qty()
    si = ida_strlist.string_info_t()
    for i in range(qty):
        if not ida_strlist.get_strlist_item(si, i):
            continue
        raw = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
        if not raw:
            continue
        try:
            t = raw.decode()
        except UnicodeDecodeError:
            continue
        if _VERSION_RE.match(t):
            return t
    return "unknown"


def dump_hpp():
    order = []
    found = {}
    missing = {}
    ns = None
    for line in _LINES:
        m = re.match(r"^--- (.+?) ---$", line)
        if m:
            ns = _NS_NAMES.get(m.group(1), m.group(1))
            if ns not in found:
                found[ns] = {}
                missing[ns] = []
                order.append(ns)
            continue
        if ns is None:
            continue
        m = re.match(r"^([A-Za-z_]\w*) = (?:REBASE\()?(0x[0-9A-Fa-f]+)\)?", line)
        if m:
            found[ns][m.group(1)] = m.group(2)
            continue
        m = re.match(r"^([A-Za-z_]\w*): ", line)
        if m:
            k = m.group(1)
            if k not in missing[ns] and k not in found[ns]:
                missing[ns].append(k)

    total = sum(len(v) for v in found.values())
    ver = _version_string()
    out = []
    out.append("#pragma once")
    out.append("/*            IDA dumper by nikky and theholytorch")
    out.append("Roblox Version:   %s" % ver)
    out.append("Total Offsets:    %d */" % total)
    out.append("")
    out.append("#include <cstdint>")
    out.append("#include <string>")
    out.append("")
    out.append("namespace Offsets {")
    out.append('    inline std::string ClientVersion = "%s";' % ver)
    priority = ["Luau", "LuaB", "LuaL"]
    ordered = [n for n in priority if n in found] + sorted(n for n in found if n not in priority)
    for nsn in ordered:
        keys = sorted(found[nsn].keys())
        miss = sorted(x for x in set(missing[nsn]) if x not in found[nsn])
        if not keys and not miss:
            continue
        width = max([len(k) for k in keys + miss] + [1])
        out.append("")
        out.append("    namespace %s {" % nsn)
        for k in keys:
            v = found[nsn][k]
            if k in _NO_REBASE:
                out.append("        inline constexpr %s %s = %s;" % (_hpp_type(nsn, k), k.ljust(width), v))
            else:
                out.append("        inline constexpr %s %s = REBASE(%s);" % (_hpp_type(nsn, k), k.ljust(width), v))
        for k in miss:
            if k in _NO_REBASE:
                out.append("        inline constexpr %s %s = 0x0; // not found" % (_hpp_type(nsn, k), k.ljust(width)))
            else:
                out.append("        inline constexpr %s %s = REBASE(0x0); // not found" % (_hpp_type(nsn, k), k.ljust(width)))
        out.append("    }")
    out.append("}")
    out.append("")

    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        try:
            here = os.path.dirname(ida_nalt.get_input_file_path())
        except Exception:
            here = os.getcwd()
    path = os.path.join(here, "IDAD DUMPER.hpp")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
        _builtin_print("[idadumper] wrote %d offsets -> %s" % (total, path))
    except Exception as e:
        _builtin_print("[idadumper] failed to write hpp: %s" % e)
    return path


def _run_all():
    for fn in (dump_tasks, dump_rbxtransport, dump_rbxtransport_layout, dump_misc, dump_raknet, dump_raycast,
               dump_instance, dump_coroutine, dump_luab, dump_global_table, dump_rtti_vtables,
               dump_lua, dump_lual, dump_engine, dump_luau_extras, dump_luau_core,
               dump_remote, dump_sky):
        try:
            fn()
        except Exception as e:
            print("! %s failed: %s" % (fn.__name__, e))


_run_all()
dump_hpp()
