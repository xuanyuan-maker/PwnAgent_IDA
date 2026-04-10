from __future__ import annotations

"""IDA 证据桥实现层。

职责：
- 从当前打开的 IDA 会话采集静态信息（函数、导入、字符串、危险调用等）
- 根据 round1 的补证请求提取 callers/callees/pseudocode
"""

from pathlib import Path
import logging
import re
from typing import Dict, Any, List, Set, Callable, TypeVar, Tuple

from .ida_bridge_interface import IDAEvidenceBridge


T = TypeVar("T")
logger = logging.getLogger("pwn_agent.ida_bridge")


class IDABridgeImpl(IDAEvidenceBridge):
    """IDA 读证据桥实现。"""

    _MANUAL_SKIP_PREFIX = "NO_"

    def __init__(self, use_mock: bool = False):
        if use_mock:
            raise RuntimeError("mock 模式已禁用；请在真实 IDA 运行时中采集证据")

    _SETUP_NAME_PATTERNS = (
        re.compile(r"^(?:_+)?init(?:_|$)", re.IGNORECASE),
        re.compile(r"^(?:_+)?fini(?:_|$)", re.IGNORECASE),
        re.compile(r"^(?:_+)?start(?:_|$)", re.IGNORECASE),
        re.compile(r"^(?:sandbox|seccomp)(?:_|$)", re.IGNORECASE),
        re.compile(r"^(?:setup|install_seccomp|configure_sandbox)(?:_|$)", re.IGNORECASE),
        re.compile(r"^__libc_csu_(?:init|fini)$", re.IGNORECASE),
    )
    _SKIP_NAME_PATTERNS = (
        re.compile(r"@plt$", re.IGNORECASE),
        re.compile(r"^\.plt", re.IGNORECASE),
        re.compile(r"^nullsub_\d+$", re.IGNORECASE),
    )
    _INPUT_HINT_PATTERN = re.compile(r"(read|recv|input|get|scan|menu|parse|copy)", re.IGNORECASE)

    def _require_ida(self):
        """检查当前是否运行在可用的 IDAPython 环境中。"""
        try:
            import idautils  # noqa: F401
            import idc  # noqa: F401
        except Exception as e:
            raise RuntimeError(f"IDA runtime unavailable: {e}") from e

    def _run_on_main_thread(self, fn: Callable[[], T]) -> T:
        """在 IDA 主线程执行函数。

        原因：部分 IDA API 只能主线程调用（例如 Hex-Rays 反编译、函数迭代）。
        """
        import idaapi

        box: Dict[str, Any] = {"ok": False, "value": None, "error": None}

        def thunk():
            try:
                box["value"] = fn()
                box["ok"] = True
            except Exception as e:
                box["error"] = e
            return 1

        idaapi.execute_sync(thunk, idaapi.MFF_FAST)

        if box["error"] is not None:
            raise box["error"]
        return box["value"]

    def base_snapshot(self, binary_path: str) -> Dict[str, Any]:
        """采集基础快照（阶段 BASE_SNAPSHOT）。"""
        def _collect() -> Dict[str, Any]:
            self._require_ida()
            import idautils
            import idc
            import idaapi

            funcs: List[str] = []
            for ea in idautils.Functions():
                name = idc.get_func_name(ea)
                if name:
                    funcs.append(name)

            imports = self._collect_imports()
            strings = self._collect_strings(limit=200)
            dangerous_calls = self._collect_dangerous_calls()
            root_function = self._guess_root_function()
            call_tree = self._build_call_tree(root_function, max_nodes=160)
            analysis_functions = call_tree["analysis_queue"]

            function_scores = self._score_functions(
                analysis_functions,
                dangerous_calls,
                depth_map=call_tree.get("depth_map", {}),
                indegree_map=call_tree.get("indegree_map", {}),
                discovery_order=call_tree.get("discovery_order", {}),
            )
            priority_functions = [item["name"] for item in function_scores]

            excluded_functions = sorted(
                [
                    name
                    for name in funcs
                    if name not in analysis_functions and self._should_skip_analysis_function(name)
                ]
            )

            inf = idaapi.get_inf_structure()
            bitness = 64 if inf.is_64bit() else 32
            entry_ea = self._get_entry_ea()

            snapshot = {
                "binary": Path(binary_path).name,
                "architecture": f"amd{bitness}" if bitness == 64 else "x86",
                "entry_point": hex(entry_ea),
                "root_function": call_tree.get("root", root_function),
                "call_tree": call_tree["tree"],
                "analysis_queue": analysis_functions,
                "postorder_functions": analysis_functions,
                "priority_functions": priority_functions,
                "function_scores": function_scores,
                "imports": imports,
                "dangerous_calls": dangerous_calls,
                "functions": analysis_functions,
                "all_functions": funcs,
                "excluded_functions": excluded_functions,
                "manual_suppressed_functions": sorted(
                    [name for name in funcs if self._is_manually_suppressed_function(name)]
                ),
                "strings": strings,
            }
            logger.info(
                "base_snapshot done: root=%s queue=%d priority=%d total_funcs=%d excluded=%d",
                snapshot.get("root_function"),
                len(snapshot.get("analysis_queue", [])),
                len(snapshot.get("priority_functions", [])),
                len(snapshot.get("all_functions", [])),
                len(snapshot.get("excluded_functions", [])),
            )
            return snapshot

        return self._run_on_main_thread(_collect)

    def collect_round2_evidence(self, requests: List[Dict[str, str]]) -> Dict[str, Any]:
        """按请求收集二次证据（阶段 ROUND2_EVIDENCE）。"""
        def _collect() -> Dict[str, Any]:
            self._require_ida()
            logger.info("collect_round2_evidence: requests=%d", len(requests))
            items: List[Dict[str, Any]] = []
            for r in requests:
                tool = (r.get("tool") or "").strip()
                target = (r.get("target") or "").strip()
                if tool == "get_callers":
                    items.append({"request": r, "result": self._get_callers(target)})
                elif tool == "get_callees":
                    items.append({"request": r, "result": self._get_callees(target)})
                elif tool == "get_pseudocode":
                    items.append({"request": r, "result": self._get_pseudocode(target)})
                else:
                    items.append({"request": r, "result": {"error": f"不支持的工具: {tool}"}})
            return {"evidence_items": items}

        return self._run_on_main_thread(_collect)

    def _get_entry_ea(self) -> int:
        """读取入口地址，兼容不同 IDA 版本 API。"""
        import idc
        import idaapi

        try:
            ea = int(idc.get_inf_attr(idc.INF_START_EA))
            if ea != idc.BADADDR:
                return ea
        except Exception:
            pass

        try:
            ea = int(idaapi.get_inf_structure().start_ea)
            if ea != idc.BADADDR:
                return ea
        except Exception:
            pass

        try:
            return int(idaapi.get_imagebase())
        except Exception:
            return 0

    def _collect_imports(self) -> List[str]:
        """收集导入符号。"""
        import ida_nalt

        out: List[str] = []

        def cb(ea, name, ord_):
            if name:
                out.append(str(name))
            return True

        qty = ida_nalt.get_import_module_qty()
        for i in range(qty):
            ida_nalt.enum_import_names(i, cb)
        return sorted(list(set(out)))

    def _collect_strings(self, limit: int = 200) -> List[str]:
        """收集字符串（限制条目数，避免上下文过大）。"""
        import idautils

        out: List[str] = []
        for s in idautils.Strings():
            try:
                out.append(str(s))
                if len(out) >= limit:
                    break
            except Exception:
                continue
        return out

    def _collect_dangerous_calls(self) -> List[Dict[str, str]]:
        """扫描危险 API 调用点（粗筛）。"""
        import idautils
        import idc

        dangerous = {
            "gets", "strcpy", "strcat", "sprintf", "scanf", "read", "recv", "system", "memcpy"
        }
        hits: List[Dict[str, str]] = []
        seen: Set[tuple[str, str]] = set()

        for f_ea in idautils.Functions():
            fname = idc.get_func_name(f_ea) or hex(f_ea)
            if self._should_skip_analysis_function(fname):
                continue
            for ea in idautils.FuncItems(f_ea):
                if idc.print_insn_mnem(ea).lower() != "call":
                    continue
                op = idc.print_operand(ea, 0) or ""
                for d in dangerous:
                    if d in op:
                        key = (fname, d)
                        if key in seen:
                            continue
                        seen.add(key)
                        hits.append({
                            "function": fname,
                            "api": d,
                            "reason": f"调用了危险 API '{d}'",
                        })
        return hits

    def _get_func_ea(self, name: str) -> int:
        """函数名 -> 函数地址。"""
        import idc

        ea = idc.get_name_ea_simple(name)
        if ea == idc.BADADDR:
            raise RuntimeError(f"function not found: {name}")
        return ea

    def _get_callers(self, target_name: str) -> Dict[str, Any]:
        """收集某函数的调用者列表。"""
        import idautils
        import idc

        target = self._get_func_ea(target_name)
        callers: Set[str] = set()
        for x in idautils.CodeRefsTo(target, 0):
            fn = idc.get_func_name(x)
            if fn and not self._should_skip_analysis_function(fn):
                callers.add(fn)
        return {"target": target_name, "count": len(callers), "items": sorted(callers)}

    def _guess_root_function(self) -> str:
        """尽量推断分析入口，优先 main。"""
        import idautils
        import idc

        for cand in ["main", "_main", "wmain", "WinMain", "_start", "start"]:
            ea = idc.get_name_ea_simple(cand)
            if ea != idc.BADADDR and not self._should_skip_analysis_function(cand):
                return cand

        entry_ea = self._get_entry_ea()
        for x in idautils.CodeRefsTo(entry_ea, 0):
            fn = idc.get_func_name(x)
            if fn and not self._should_skip_analysis_function(fn):
                return fn

        for ea in idautils.Functions():
            fn = idc.get_func_name(ea)
            if fn and not self._should_skip_analysis_function(fn):
                return fn
        return "main"

    def _is_user_code_function(self, func_name: str) -> bool:
        """粗略过滤明显的导入/外部/plt/thunk 函数。"""
        import idaapi
        import idc
        import ida_segment

        name = str(func_name or "").strip()
        if not name:
            return False
        if name.startswith(("j_", "__imp_", "nullsub_", ".")):
            return False
        if any(p.search(name) for p in self._SKIP_NAME_PATTERNS):
            return False

        ea = idc.get_name_ea_simple(name)
        if ea == idc.BADADDR:
            return False
        func = idaapi.get_func(ea)
        if func is None:
            return False
        if getattr(func, "flags", 0) & getattr(idaapi, "FUNC_THUNK", 0):
            return False

        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg) if seg else ""
        bad_seg_markers = {".plt", ".plt.sec", ".idata", "extern", ".got", ".got.plt", "IMPORT", ".init", ".fini"}
        return seg_name not in bad_seg_markers

    def _is_manually_suppressed_function(self, func_name: str) -> bool:
        """识别用户手工标记为不需要自动分析的函数。"""
        name = str(func_name or "").strip()
        return bool(name) and name.startswith(self._MANUAL_SKIP_PREFIX)

    def _is_trivial_function(self, func_name: str) -> bool:
        """判定空函数/桩函数：仅少量无副作用指令（ret/jmp/nop/endbr 等）。"""
        import idaapi
        import idautils
        import idc

        ea = idc.get_name_ea_simple(func_name)
        if ea == idc.BADADDR:
            return True
        func = idaapi.get_func(ea)
        if func is None:
            return True

        insns = []
        for i, item_ea in enumerate(idautils.FuncItems(ea)):
            if i >= 10:
                break
            mnem = (idc.print_insn_mnem(item_ea) or "").lower().strip()
            if mnem:
                insns.append(mnem)

        if not insns:
            return True
        if len(insns) <= 2 and all(m in {"ret", "retn", "jmp", "nop", "endbr64", "endbr32"} for m in insns):
            return True

        noise = {"push", "mov", "sub", "add", "leave", "ret", "retn", "nop", "endbr64", "endbr32", "jmp"}
        # 仅由函数序言/结尾和跳转组成，且非常短，视为空壳。
        if len(insns) <= 4 and all(m in noise for m in insns):
            return True
        return False

    def _should_skip_analysis_function(self, func_name: str) -> bool:
        """过滤无需进入模型分析的函数：导入/跳板/初始化/空函数。"""
        name = str(func_name or "").strip()
        if not name:
            return True
        if self._is_manually_suppressed_function(name):
            return True
        if not self._is_user_code_function(name):
            return True
        if any(pattern.search(name) for pattern in self._SETUP_NAME_PATTERNS):
            return True
        return self._is_trivial_function(name)

    def _get_callees(self, func_name: str) -> Dict[str, Any]:
        """收集某函数调用了哪些函数（按调用点出现顺序）。"""
        import idautils
        import idc

        f_ea = self._get_func_ea(func_name)
        callees: List[str] = []
        seen: Set[str] = set()
        for ea in idautils.FuncItems(f_ea):
            if idc.print_insn_mnem(ea).lower() != "call":
                continue
            opnd = (idc.print_operand(ea, 0) or "").strip()
            if not opnd or not self._is_user_code_function(opnd) or self._should_skip_analysis_function(opnd):
                continue
            if opnd in seen:
                continue
            seen.add(opnd)
            callees.append(opnd)
        return {"target": func_name, "count": len(callees), "items": callees}

    def _build_call_tree(self, root_name: str, max_nodes: int = 160) -> Dict[str, Any]:
        """从 root 开始构建调用树，并生成“叶子优先队列”。

        队列规则（程序侧实现，非模型侧）：
        1) 包含 root 在内的全部可达节点
        2) 按深度从深到浅排序（越靠近叶子越先分析）
        3) 同深度按首次发现顺序稳定排序

        例如：
            main -> a,b,c; b -> d,e
        输出队列：
            [d, e, a, b, c, main]
        """
        seen: Set[str] = set()
        active_path: Set[str] = set()
        discovery_order: Dict[str, int] = {}
        depth_map: Dict[str, int] = {}
        indegree_map: Dict[str, int] = {}
        node_count = 0
        order_id = 0

        def dfs(name: str, depth: int) -> Dict[str, Any]:
            nonlocal node_count, order_id
            clean = str(name or "").strip()
            if not clean:
                return {"name": "unknown", "children": []}

            # 环检测：递归回边直接截断
            if clean in active_path:
                return {"name": clean, "children": []}

            if clean in seen:
                # 多父节点场景：保持树稳定，不重复展开
                depth_map[clean] = max(depth_map.get(clean, depth), depth)
                return {"name": clean, "children": []}

            if node_count >= max_nodes:
                return {"name": clean, "children": []}

            seen.add(clean)
            active_path.add(clean)
            node_count += 1
            discovery_order[clean] = order_id
            order_id += 1
            depth_map[clean] = max(depth_map.get(clean, depth), depth)
            indegree_map.setdefault(clean, 0)

            try:
                callees = self._get_callees(clean).get("items", [])
            except Exception:
                callees = []

            children = []
            for child in callees:
                child_name = str(child).strip()
                if self._should_skip_analysis_function(child_name):
                    continue
                indegree_map[child_name] = indegree_map.get(child_name, 0) + 1
                children.append(dfs(child_name, depth + 1))

            active_path.discard(clean)
            return {"name": clean, "children": children}

        start_name = root_name if not self._should_skip_analysis_function(root_name) else self._guess_root_function()
        tree = dfs(start_name, depth=0)

        # 构建叶子优先分析队列：深度越深优先；同深度按发现顺序。
        # 注意：按需求“包含 root 节点（通常在队列末尾）”。
        queue_nodes = list(seen)
        analysis_queue = sorted(queue_nodes, key=lambda n: (-depth_map.get(n, 0), discovery_order.get(n, 10**9)))

        return {
            "tree": tree,
            "postorder": analysis_queue,  # 兼容旧字段名
            "analysis_queue": analysis_queue,
            "root": start_name,
            "depth_map": depth_map,
            "discovery_order": discovery_order,
            "indegree_map": indegree_map,
        }

    def _score_functions(
        self,
        functions: List[str],
        dangerous_calls: List[Dict[str, str]],
        *,
        depth_map: Dict[str, int],
        indegree_map: Dict[str, int],
        discovery_order: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """对函数进行程序侧打分，并返回优先级列表（高分优先）。

        评分维度：
        - 危险调用命中次数（权重最高）
        - 调用树深度（越深越靠近叶子）
        - 被调用次数（入度，近似衡量汇聚点）
        - 名称输入提示（read/input/recv 等）
        """
        dangerous_hits: Dict[str, int] = {}
        for item in dangerous_calls:
            if not isinstance(item, dict):
                continue
            fn = str(item.get("function", "")).strip()
            if not fn:
                continue
            dangerous_hits[fn] = dangerous_hits.get(fn, 0) + 1

        scored: List[Dict[str, Any]] = []
        for name in functions:
            clean = str(name).strip()
            if not clean:
                continue
            depth = int(depth_map.get(clean, 0))
            indegree = int(indegree_map.get(clean, 0))
            danger = int(dangerous_hits.get(clean, 0))
            input_hint = 1 if self._INPUT_HINT_PATTERN.search(clean) else 0

            # 程序侧硬规则评分（可后续通过配置参数化）。
            score = danger * 100 + depth * 10 + indegree * 4 + input_hint * 6
            scored.append(
                {
                    "name": clean,
                    "score": score,
                    "depth": depth,
                    "danger_hits": danger,
                    "caller_count": indegree,
                    "input_hint": bool(input_hint),
                }
            )

        scored.sort(
            key=lambda x: (
                -int(x.get("score", 0)),
                -int(x.get("depth", 0)),
                int(discovery_order.get(str(x.get("name", "")), 10**9)),
            )
        )
        return scored

    def _clean_ida_tags(self, s: str) -> str:
        """清理 IDA 行文本中的颜色/标签控制符。"""
        try:
            import ida_lines
            return ida_lines.tag_remove(s)
        except Exception:
            try:
                import idaapi
                return idaapi.tag_remove(s)
            except Exception:
                return s

    def _get_pseudocode(self, func_name: str) -> Dict[str, Any]:
        """优先取伪代码；失败时退化为反汇编片段。"""
        import ida_hexrays
        import idautils
        import idc

        f_ea = self._get_func_ea(func_name)
        func_ea = hex(f_ea)

        try:
            cfunc = ida_hexrays.decompile(f_ea)
            lines = [self._clean_ida_tags(str(x.line)).rstrip() for x in cfunc.get_pseudocode()][:120]
            text = "\n".join([ln for ln in lines if ln])
            return {"target": func_name, "kind": "pseudocode", "function_ea": func_ea, "text": text}
        except Exception:
            pass

        asm = []
        for i, ea in enumerate(idautils.FuncItems(f_ea)):
            if i >= 180:
                break
            dis = self._clean_ida_tags(idc.generate_disasm_line(ea, 0) or "")
            asm.append(f"{hex(ea)}: {dis}")
        return {"target": func_name, "kind": "asm", "function_ea": func_ea, "text": "\n".join(asm)}
