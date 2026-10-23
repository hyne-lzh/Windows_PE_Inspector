# GUI 与 CLI 系统性检查报告

> 范围严格限定在 **GUI（`ui/gui.py`、`main.py`）** 与 **CLI（`cli/cli.py`、`cmd_main.py`）** 两部分，
> 不重复核心解析层（`achieve/pe_parser.py`）的代码逻辑审查，但会记录其在 GUI/CLI **表现层**的连锁问题。
> 通用工程问题（零测试/无 CI、版本漂移等）见 `问题.md`；运行时可用性见 `冒烟测试问题.md`；
> 本文聚焦**这两个入口自身的代码质量、功能正确性与潜在缺陷**。

---

## 检查记录 2026-10-23（GUI/CLI 专项）

**样本**：`test/` 下 23 个真实 PE（含 6 个 UPX 样本、32/64 位混合）
**方法**：通读全部 GUI/CLI 源码（gui.py 1119 行、cli.py 320 行、main.py 46 行、cmd_main.py 13 行）+ 实跑验证 + 对照 `assets/i18n.json` 翻译键

### 问题清单索引

| # | 问题标题 | 严重程度 | 位置 | 状态 |
|---|---------|---------|------|------|
| G1 | 解析进行中拖入/浏览新文件被静默丢弃，路径框与报告内容不一致 | **高** | `ui/gui.py:483-485` + `_on_drop`/`_browse` | 已确认 |
| G2 | 截断/损坏 PE 在 GUI 与 CLI 中静默显示"节区数声明≠实际"，无告警 | **中** | `_render_info` / `show_header` 未做一致性校验 | 已确认 |
| G3 | GUI 解析无取消、无超时；worker 卡死时 `_poll` 永久 100ms 轮询，界面锁死 | **高** | `ui/gui.py:521-580` 线程模型 | 已确认（与 `问题.md` 严重项交叉，此处给 GUI 侧修复） |
| G4 | 解析进行中切换语言，报告正文语言与界面语言不一致 | 低 | `_switch_language:384-385` | 已确认 |
| G5 | CLI `--export` 默认抑制所有展示区块，用户可能预期"既看又导出" | 低 | `cli/cli.py:281-285` | 已确认（设计权衡） |
| G6 | CLI 英文模式下可疑原因括号风格不一致（开全角、闭半角） | 低 | `cli/cli.py:121-122` 硬编码 `）` | 已确认 |
| G7 | `run_gui(preload)` 的 `preload` 参数在 `main.py` 中从未接入，属死参数 | 低 | `ui/gui.py:1097` vs `main.py` | 已确认 |

---

### G1：解析进行中拖入/浏览新文件被静默丢弃，路径框与报告内容不一致

- **严重程度**：**高** —— 安全分析工具的"归因错误"风险：界面显示 A 文件、展示的却是 B 文件结果，全程无提示。
- **复现步骤**：
  1. 启动 GUI，先解析慢样本 `test/15_mshtml.dll_32bit`（约 3.8 s，期间 `btn_analyze` 为 `disabled`）；
  2. 解析尚未结束时拖入 `test/01_kernel32.dll`（或点"浏览"选它）；
  3. 等第一次解析完成，观察路径框与右侧报告。
- **实际表现**：路径框变为 `01_kernel32.dll`，报告仍是 `15_mshtml`（节区数 6）。`_generation` 未递增（实测 `False`），状态栏无任何提示。
- **预期表现**：要么取消旧任务改解析新文件，要么明确提示"解析中，请稍候"，且路径框不应停在会误导用户的新文件名上。
- **根因分析**：`ui/gui.py:483-485`

  ```python
  def _on_analyze(self) -> None:
      if self._worker is not None and self._worker.is_alive():
          return                      # 只防重入，不取消、不提示
  ```

  而 `_on_drop:413-420` 与 `_browse:448-456` 都是**先 `self.path_var.set(path)` 再调 `_on_analyze()`** —— 路径已改写，解析请求却被丢弃，二者脱节。worker 启动时用的是守卫判定之前的旧 `path`（闭包 `args=(path, gen)`），故渲染的永远是旧文件。
- **建议修复**：守卫命中时改为"取消旧代次并重启新任务"——`self._generation += 1; gen = self._generation;` 然后启动新 worker（已存在的 `_poll` 代次不匹配会自动丢弃旧结果，机制可靠），并在状态栏写明"已切换解析目标"；两条文件入口统一收敛到一个 `_request_analyze(path)` 方法，避免行为分叉。

---

### G2：截断/损坏 PE 在 GUI 与 CLI 中静默显示"节区数声明≠实际"，无告警

- **严重程度**：**中** —— 不会崩溃，但"分析成功"的假象成立；截断样本被当成"没有节区/没有导入表"极易误判。
- **复现步骤**：取 `test/01_kernel32.dll` 前 512 字节存为 `trunc512.dll`，分别用 CLI 与 GUI 打开。
- **实际表现**：退出码 0，基本信息显示「**节区数量 : 8**」，但节区表为空；导入/导出/调试均"无"；`report.warnings` 为空，无任何"疑似截断"提示。（`num_sections=8` 取自文件头声明，`len(sections)=0` 因为节区表越过文件尾被 pefile 静默丢弃。）
- **预期表现**：显示层应识别 `num_sections != len(sections)` 并在头部/状态栏给出醒目告警。
- **根因分析**：`ui/gui.py:_render_info` 直接渲染 `report.num_sections`，CLI `cli/cli.py:show_header` 同样直接打印 `r.num_sections`；两者都未与 `len(report.sections)` 做一致性校验。核心层 `parse_pe` 也不会对"节区声明数与可解析数不符"报错（静默返回空列表，绕过了 `_build_report` 外的异常处理）。
- **建议修复**：
  - 核心层（`pe_parser`）：`_build_report()` 末尾加 `if len(sections) != int(fh.NumberOfSections)` → 追加 `warnings`（"节区声明 N 实际 M，文件疑似截断"）；并对每个节区校验 `PointerToRawData+SizeOfRawData <= file_size` 越界告警（注：此为表现层以外的根因修复，建议与 `冒烟测试问题.md` 第 2 条合并处理）。
  - **GUI/CLI 表现层（本文件职责）**：在 `_render_info` 与 `show_header` 中，若检测到声明节区数与实际不符，加一行红色告警文案，而不是只显示声明值。即使核心层短期未修，表现层也能先给出可见提示。

---

### G3：GUI 解析无取消、无超时；worker 卡死时界面永久锁死

- **严重程度**：**高** —— 遇到解析异常缓慢或 pefile 卡死的文件，界面永久停留在"解析中"，进度条一直转、分析按钮一直禁用，用户只能杀进程。
- **复现条件**：一个让 `parse_pe` 长时间不返回的 pathological PE（如超大文件或触发 pefile 内部死循环的样本）。
- **实际表现**：`_on_analyze` 启动 worker 后，`_poll` 每 100ms 轮询；若 worker 既不 `put` 也不退出，`_poll` 在 `ui/gui.py:541` 无限 `self.after(100, lambda: self._poll(gen))`，`btn_analyze` 始终 `disabled`，`progress` 始终 `start()`。无"取消"按钮、无超时兜底。
- **根因分析**：线程模型（`ui/gui.py:6-14, 283-285, 521-580`）只有"代际"防串味机制，没有超时与取消。worker 是 `daemon=True`，主线程无法主动中断解析线程（Python 无强制线程终止），因此一旦卡死只能等进程退出。
- **建议修复（GUI 侧，务实方案）**：
  - **超时兜底**：在 `_poll` 中记录"解析开始时间"，超过阈值（如 30s）仍未出结果，则把状态栏改为"解析超时，请切换文件重试"，并允许再次点击"分析"——实现方式是：超时后把 `_worker` 记为"已放弃"（不再等待其消息），放行下一次 `_on_analyze`（当前守卫只认 `is_alive()`，需改为同时允许"已超时"的 worker 被覆盖）。
  - **取消按钮**：解析中把"分析"按钮改为"取消"，点击后递增 `_generation`（使旧 worker 结果在 `_poll` 被丢弃）并解除忙碌态；旧 worker 作为 daemon 线程在 parse 返回后自然结束。
  - 这是 `问题.md` 已记载的"严重"项，此处给出 GUI 实现层的具体落点。

---

### G4：解析进行中切换语言，报告正文语言与界面语言不一致

- **严重程度**：低（仅显示语言不一致，不影响分析正确性；重新点一次"分析"即恢复）
- **复现步骤**：解析 `test/15_mshtml.dll_32bit` 期间，把右上角语言切到 English，等解析完成。
- **实际表现**：工具栏/分页名变英文，但报告正文（节区含义、高危 API 说明等）仍是中文——因为它是旧 worker 用旧语言解析出来的；期间 `_switch_language` 已把 `_report` 置 `None`，新语言的重新解析被 `ui/gui.py:484` 守卫静默丢弃。
- **根因分析**：与 G1 同源——`_switch_language:384-385` 在 worker 存活时调 `_on_analyze()` 被丢弃。
- **建议修复**：随 G1 一并修复（让 `_on_analyze` 支持"取消旧代次并重新发起"），语言切换会自动以新语言重解析，本问题随之消失。

---

### G5：CLI `--export` 默认抑制所有展示区块

- **严重程度**：低（设计权衡，非崩溃）
- **复现**：`python cmd_main.py test/01_kernel32.dll --export out.html`（不带 `--all` 或任何区块 flag）。
- **实际表现**：因 `cli.py:281-285` 的 `show_all = args.all or not (... or args.export)`，只要给了 `--export` 就使 `show_all=False`，且未显式指定区块 flag，于是**屏幕只打印导出成功提示、不显示任何解析结果**。
- **预期/争议**：多数用户预期"既看到结果又拿到文件"。
- **建议修复**：把 `args.export` 从"抑制显示"的条件中移除——`--export` 只决定"是否导出"，显示仍按"无任何区块 flag → 全显"的默认逻辑走；或在文档/help 中明确告知"--export 单独使用时只导出不显示"。

---

### G6：CLI 英文模式下可疑原因括号风格不一致

- **严重程度**：低（纯展示瑕疵）
- **代码**：`cli/cli.py:121-122`

  ```python
  print(f"  {s.name} : {t('cli.suspect_prefix')}"
        + t("cli.suspect_join").join(s.suspicious_reasons) + "）")
  ```

  `cli.suspect_prefix` 中文为 `可疑（`、英文为 `suspicious (`（半角开括号），而**闭合括号是硬编码中文全角 `）`**。
- **实际表现**：英文模式下输出形如 `suspicious (W+X; 可写节区）` —— 开半角、闭全角，括号不匹配。
- **建议修复**：闭合括号也走翻译键（新增 `cli.suspect_suffix`，zh=`）`、en=`）`），或统一用 ASCII 括号。

---

### G7：`run_gui(preload)` 的 `preload` 参数从未接入

- **严重程度**：低（死代码/预留未接通）
- **代码**：`ui/gui.py:1097` 定义 `def run_gui(preload: str | None = None)`，并在 `1114-1116` 用 `if preload:` 设 `path_var` 并 `after(0, _on_analyze)`；但 `main.py:42` 调用 `run_gui()` 时**从不传 `preload`**，故该参数永远为 `None`，整段 `preload` 逻辑是死代码。
- **建议修复**：要么在 `main.py` 接入（例如支持 `main.py <文件>` 直接预载），要么删除该参数与相关分支，避免误导维护者。

---

## 已复核并排除（非本文件缺陷，避免误报）

- **CLI `show_risks` 英文摘要计数错误**：初判风险摘要硬编码中文键 `by_level={"严重":...}` 在英文下会全 0。复核确认 `risk_level` 是恒为**中文的数据值**（`pe_parser.py:388` 注释明确），计数在 zh/en 下均正确；且 `risk.严重/中等/低` 在 i18n 中均有 en 映射（Critical/Medium/Low），列显示也正确。**非缺陷。**
- **CLI `strings.summary` 的 `{counts}`**：模板确实含 `{counts}`，CLI 以 `counts=""` 显式传入以抑制该段（详细分类在下方另打印）。属刻意设计，非缺陷（仅耦合略脆）。
- **`clear_view` 在渲染前调用导致内容丢失**：`_on_analyze` 调 `clear_view()` 仅做"分析开始"占位，真正内容由 `_poll` 中的 `render()` 重建，逻辑自洽。
- **`_apply_search` 旧树回调**：分页重建后旧 `var.trace_add` 闭包引用的 `tree` 已 `destroy()`，`winfo_exists()` 返回 False 提前返回，无异常、无泄漏。

---

## GUI/CLI 代码质量观察（正面）

- **线程契约清晰**：解析严格在 daemon 线程，只经 `self._queue` 回传，主线程 `_poll` 更新 widget，无跨线程 widget 访问（G3 是"缺超时"问题，不是线程安全问题）。
- **代际机制（P1-4）落地正确**：`_generation` + 消息携带代次 + `_poll` 双重代次校验，实测能正确丢弃过期结果（G1/G4 是"丢弃过头"而非"串味"）。
- **异常兜底完善**：`_log_exception` 写 `%LOCALAPPDATA%\PEInspector\`，`main.py`/`run_gui` 对启动期 ImportError 与建窗异常均有原生弹窗（打包后无控制台可见）。
- **拖放解析健壮**：`parse_dropped_files` 正确处理 Windows 含空格路径的 `{}` 包裹与多文件分隔；tkdnd 缺失优雅降级（P1-5）。
- **i18n 架构正确**：`_BUILTIN_TRANSLATIONS` + 外置 `i18n.json` 双层、缺失回落；zh/en 键对齐 202/202。
- **CLI 退出码规约清晰**：0 成功 / 1 文件或依赖 / 2 非有效 PE，并在 `parse_pe` 的 `PeParseError` 上带 `exit_code`。

---

## 单元测试补充（覆盖率提升）

新增 `tests/test_gui.py` 与 `tests/test_cli.py`（标准库 `unittest`，无需 pytest），共 **34 个用例**，全部通过：

| 模块 | 用例数 | 覆盖点 |
|------|-------|--------|
| `tests/test_gui.py` | 17 | `parse_dropped_files`（6 种路径/空格/引号/多文件）、`_row_hit`/`_filter_rows`（列表+树形）、`_log_path`（落 LOCALAPPDATA、不写 cwd）、`_make_exception_handler`、`MainWindow._signature_text`、主题配置、集成渲染（构造主窗口→解析→`render`→校验节区表行数==节区数）、英文渲染不抛异常 |
| `tests/test_cli.py` | 17 | 9 个 `show_*` 渲染函数（不抛异常+关键字段）、子进程退出码（`--version`=0 / 有效文件=0 / 缺失=1 / 非 PE=2）、`--export` 单独使用抑制展示（固化 G5 现状）、截断 PE 一致性（固化 G2：声明节区数≠实际，且无告警） |

> **运行方式（重要）**：因 `customtkinter`/`Tk` 在同一进程内多次建窗会残留事件循环状态，**两个套件需分开运行**，不要一次 `unittest discover` 全跑：
> `.venv/Scripts/python.exe -m unittest tests.test_gui` 与 `tests.test_cli` 分别执行（GUI 集成用例在无显示环境下自动跳过）。
> 测试临时样本读取 `test/` 目录，不新增任何运行期依赖。

---

## 冒烟测试（GUI/CLI 核心功能启动与运行）

执行时间：2026-10-23｜环境：Windows / `.venv` Python 3.11.4 / customtkinter 6.0.0｜结果：**12/12 通过**

| # | 检查项 | 结果 | 说明 |
|---|--------|------|------|
| 1 | CLI `--version` 退出码 0 | PASS | 输出版本 `0.6.0` |
| 2 | CLI 中文全量解析 | PASS | 退出 0，含「基本信息」「节区」等 |
| 3 | CLI 英文模式 | PASS | 退出 0，含 `Basic`/`Size` 英文文案 |
| 4 | CLI 导出 HTML | PASS | 生成 356 KB 报告文件 |
| 5 | CLI 缺失文件退出码 1 | PASS | 符合退出码规约 |
| 6 | GUI 主窗口启动 | PASS | `MainWindow()` 正常构造 |
| 7 | GUI 拖放路径解析 | PASS | `{含空格路径}` 与多文件分隔解析正确 |
| 8 | GUI 解析+渲染 kernel32 | PASS | `_report` 生成，节区 8 个 |
| 9 | GUI 节区表行数一致 | PASS | Treeview 行数(8) == 节区数(8) |
| 10 | GUI 空闲态语言切换→英文 | PASS | `i18n` 切到 en |
| 11 | GUI 导出报告 | PASS | 生成 4.2 KB HTML |
| 12 | GUI 解析中拖入被丢弃（G1 复核） | PASS（行为确认） | `gen` 未递增，确认 G1 现象可稳定复现 |

### 冒烟结论

- **核心启动与运行均正常**：CLI 与 GUI 入口可启动，解析、渲染、导出、双语切换、拖放路径解析、退出码规约全部按预期工作；无启动崩溃、无未捕获异常。
- **G1 行为在冒烟中稳定复现**：解析进行中拖入新文件被静默丢弃（代次未递增），与 `gui和cli问题.md` G1 记录一致——属已知缺陷，非回归。
- **与既有报告的关系**：本文件 G1/G2/G3 与 `冒烟测试问题.md` 第 1/2 条、`问题.md` 的"GUI 解析无法取消/无超时"严重项互为交叉验证；修复时建议统一处理，避免重复改动。
