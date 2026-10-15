# 国密检测模块（2026-10-12）

模块位于 `qcs/guomi/`，默认随 `./qcs scan` 运行，沿用现有 JSON/CSV。
新增 SM2、SM3、SM4；原十算法评测范围保持不变。

2026-10-12 后续修复：两份去符号 SM2 漏检现已修复，组员 ELF 国密集合从 50/52 提升到 52/52，国密 TP/FP/FN 为 12/0/0。x86_64 参考依据编译对象的重定位记录排除已核实的日志路径、函数名、格式字符串及 stdio 指针初值，兼容有依据的 64 位 RIP MOV/LEA 链接器松弛；密码运算指令及 SM3/SM4 算法数据约束保留。这是已知实现跨路径/链接方式的修复，尚未扩展到其他架构的同类松弛或未知实现语义分析。

新增 24 份不同路径、O0/O2、静态/共享链接的去符号 SM2 回归全部通过；另用实际保留的非执行数据、通用 SM2 曲线算术、ECDSA/大数及指令篡改作对照。**早先下面两份“仅数据”对照因链接器 GC 丢失数据而不能有效证明误报边界**，旧输出保留；修正后的对照明确检查数据真实存在且未误报。最新全算法 ELF 集合为 42/52，非国密缺口仍在；87 项测试、11 步验收通过。详见工作区 `doc/2026-10-12-sm2-stripped-fix.md` 与 `artifacts/guomi-sm2-fix-20261012/verification-final/summary.json`。以下初次集成结果保留作历史对照。

## 参考资料与融合

| 参考方案 | 有用部分及采用方式 | 边界 |
| --- | --- | --- |
| cipher1 的 Semgrep + API 规则 | 核对 GmSSL 国密操作 API，并入现有 C/C++ lexer、ELF/PE 符号引擎 | 未安装 Semgrep；定义名称不证明实现 |
| cipher1 的 YARA 国密扩展 | SM3 IV、SM4 S 盒/FK/CK、SM2 曲线参数，另写 `constants.yar` | 单独命中只作为线索，避免表格数据误报实现 |
| crypto-reverse-mcp | 审查 `sm-crypto` API，独立编写 JS AST/作用域解析 | 不运行 MCP/Node/目标 JS；处理普通 SM3、别名及注释/字符串干扰，不猜测通用 encrypt 为 RSA |
| Binary Ninja CryptoScan | 审查上游常量配置与分析思路 | 未安装、集成或实测原生插件，不能把本模块成绩归给 CryptoScan |
| GmSSL 固定源码 | 审查实际国密操作，另建源码/全函数指纹参考 | 已知实现识别，不是通用算法语义推断 |

上游提交、归档 SHA-256 及链接在 `provenance.json`，MIT/Apache-2.0 许可和署名在 `licenses/`。
新代码沿用项目许可。组员资料未改，三份 ZIP 解压在 `artifacts/guomi-integration-20261012/provided/`。

## 证据与范围

- **API 引用**：C/C++ 精确操作调用、OpenSSL 国密构造器/明确选择器、ELF/PE 导入符号；JS 明确导入 `sm-crypto` 后的实际调用。调用 API 不表示当前文件实现了算法。
- **源码实现**：完整 GmSSL `sm3.c`、`sm4.c`、`sm2_sign.c`、`sm2_enc.c` 的 SHA-256 及审核定义位置匹配；改名可识别，修改内容后不再获得该证明。
- **二进制实现**：`guomi_function_signature` 在可执行区域核对整函数，沿用重定位位掩码、实际引用数据约束及角色组合。SM3 要有压缩/收尾，SM4 要有密钥扩展/分组运算，SM2 要有特定签名/验签或加解密操作。
- **线索**：单独 IV、S 盒、轮常量、曲线参数、缺少必要角色的函数命中只保留候选，`algorithm=null`，不进入实现预测。

GmSSL 提交为 `24ae482701a7b124826c382fffc55c19f76d475d`。
函数参考使用 Zig 0.13.0/Clang 18.1.6，覆盖 x86_64、AArch64、ARM、Thumb、MIPS 小端/大端 ELF；
O0/O2/Os，SM3/SM4 默认及 small-footprint，SM2 默认配置，108 个组合、152 条唯一签名。
单模块可能有未链接的辅助函数导入；静态匹配不证明它可独立运行、密码实现符合标准或被实际使用。
已定义符号沿用既有证据规则，名称本身不能证明密码语义。

JS 依赖 `tree-sitter==0.25.2` 和 `tree-sitter-javascript==0.25.0`，支持 `.js/.cjs/.mjs`、
显式 require/ESM 导入、const 静态别名、静态属性及普通 `sm3(...)`。
参数/局部变量遮蔽、var 提升和显式属性改写作保守处理；注释、字符串、正则、纯模板文本不计调用。
动态导入/属性、可变绑定、重导出、运行时 eval/反射、跨文件依赖及完整数据流未求解。
每文件 AST 上限 4 MiB，语法/UTF-8 错误返回 partial；运行时使用始终 unknown。

固件及目录复用现有递归链路，可分析解包后 C/C++、JS、ELF/PE，没有新增提取格式。
目前没有 Guomi 的 PE/Xtensa 函数参考，不能声称去符号国密实现覆盖。
未知库、其他编译器/版本、LTO、内联和混淆仍可能漏检。

## 结果与口径

表中比较 **SM2/SM3/SM4 集合**。C/JS 是 API 引用，ELF 是实现包含，不能混成一个准确率。

| 组别 | 实测量 | 国密集合匹配 | 说明 |
| --- | ---: | ---: | --- |
| 组员 C/C++ | 18 | 18/18 | TP=8、FP=0、FN=0，含阴性 |
| 组员 ELF | 52 | 50/52 | TP=10、FP=0、FN=2，precision=100%、recall=83.33% |
| 组员 JS | 22 | 22/22 | TP=19、FP=0、FN=0，全部算法亦 22/22 |
| 模拟 SquashFS 的 JS 入口 | 5 | 5/5 | 复用上述五份 JS，不增加独立样本；未标注全镜像 |
| 重新链接并去符号的 GmSSL | 108 组合、105 个不同哈希 | 108/108；去重 105/105 | 与参考共享库/编译器/配置，只验证布局变化 |
| 常量及机器码存为非执行数据 | 2 | 2/2 | 未误报实现 |

`sm2_O0_stripped.elf`、`sm2_O2_stripped.elf` 仍漏检。
ZIP 实际提供 52 个 ELF；manifest 另列五个未提供的场景 ELF，报告保留缺失库存。
机器报告还保存全部算法集合：C 为 13/18，ELF 为 40/52；本轮未修复非国密缺口。
这些结果属于工程回归，不是独立盲测。原独立验证召回率 16.05% 的结论仍成立，
本轮未使用 `validation_set` 建库或调参。

结果在 `artifacts/guomi-integration-20261012/verification/summary-with-distinct-counts.json`，
逐对象报告在 `reports/`；77 项测试、11 步验收在 `acceptance-final/`。

## 使用与复现

```bash
./qcs doctor
./qcs scan /path/to/code.c --output source.json
./qcs scan /path/to/security.cjs --output javascript.json
./qcs scan /path/to/program.elf --output binary.json --csv binary.csv
./qcs scan /path/to/firmware.squashfs --output firmware.json
```

运行依赖已加入锁文件/安装元数据，规则和参考随包安装。
参考重建只读固定 GmSSL 源码，不读取组员测试文件或独立验证集。
按 `provenance.json` 的 URL/归档哈希取得源码，解压到
`artifacts/guomi-integration-20261012/upstream/gmssl/`，逐文件锁要求源码不变。

```bash
LD_LIBRARY_PATH="$PWD/.qcs-python312/usr/lib/qcs-compat" \
  quantum-crypto-scanner/.venv-qcs/bin/python quantum-crypto-scanner/tools/build_guomi_references.py
LD_LIBRARY_PATH="$PWD/.qcs-python312/usr/lib/qcs-compat" \
  quantum-crypto-scanner/.venv-qcs/bin/python quantum-crypto-scanner/tools/verify_guomi.py \
  --output-dir quantum-crypto-scanner/artifacts/guomi-integration-20261012/verification-rerun
```

普通 Python 3.12 可省略本环境的 `LD_LIBRARY_PATH`。验证需要复制出的组员资料和参考构建产物；
日常扫描只依赖随包数据。失败准备日志与最终成功结果都保留，复核请用新输出目录。

已有参考构建时可重新提取而不重编译：

```bash
LD_LIBRARY_PATH="$PWD/.qcs-python312/usr/lib/qcs-compat" \
  quantum-crypto-scanner/.venv-qcs/bin/python quantum-crypto-scanner/tools/build_guomi_references.py \
  --reuse-reference-builds quantum-crypto-scanner/artifacts/guomi-integration-20261012/reference-build-log.json \
  --audit-output-dir quantum-crypto-scanner/artifacts/my-guomi-extraction
```

该命令会更新当前国密数据库，先核对固定源码和原始参考二进制哈希，审计排除项及对象哈希写入指定新目录；不读取测试二进制生成签名。

## 2026-10-12 跨实现开发扩充

新增 OpenSSL、wolfSM 和 Libgcrypt 开发源码，wolfSSL 只作构建依赖。9 个新的国密源码模块进入 development_source_references.json；126 个构建（6 种架构、O0/O2/Os，含 wolfSM small 配置）产生 211 条唯一整函数参考，放入 development_function_signatures.json，原 GmSSL 数据库保留。全函数参考仍对未知版本、编译器和布局敏感。

新增 C/C++ 本地 AST 和 ELF/PE 本地指令数据流识别。SM3 检查同一输入的完整 P0/P1 旋转多项式、P0 的加法输入、7/12/19 旋转、布尔/加法/XOR 轮计算及轮界限；SM4 检查完整 256 项 S 盒、32 项 CK 或标准 L/L-prime 查表，要求代码实际读取并参与变换。XOR 重结合、互补移位形成旋转、已核实的字节拼装和双移位可归一化。常量单独命中仍不进入国密实现预测。源码会有限展开本文件定义的宏和辅助函数，也不猜测外部旋转辅助函数的行为。

SM2 新增绑定签名输入、组合点、仿射坐标和比较的 OpenSSL BN/EC 验签调用关系；新增 wolfSM 整函数参考。尚未实现任意无符号 SM2 大整数/椭圆曲线机器码的通用方程恢复。SM2 方程证据以实际 BN/EC 操作 API 的数学含义为前提，对本地同名函数遮蔽作排除。

guomi_source_semantic/source_operation_graph 和 guomi_semantic/binary_instruction 是有预算的局部运算见证及代码邻域启发式，不是完整 CFG/语义证明。2026-10-13 源码新增受限的本地头文件宏/标量辅助函数上下文，实际调用才展开，未完整预处理；不支持的指令和普通控制流连接会丢弃状态。指令侧已有 x86_64、AArch64、ARM/Thumb、MIPS 两端序的有限提升；支持解析某架构不等于该架构检出率相同。PE64 路径可用但本轮未建立 PE 独立成绩，Xtensa 尚无该提升器。

开发数据位于 samples/guomi-development-20261012，263 个不同文件：132 个国密阳性，131 个国密阴性，20 份源码和 243 份去符号 ELF。开发构建不执行目标文件，原始上游及许可证保留。OpenSSL 构建覆盖层只提供头声明/配置，OPENSSL_cleanse 使用 memset 辅助替代；未替换密码算法函数。开发成绩不能作为独立验证成绩。

原五项目 791 文件验证集及首轮 0% 召回结果保留。新版冻结及固定验证集复测单独保存至 validation_set/guomi-improved-20261012；不得把复测称为新的独立盲测，也不得在查看复测结果后再修改本轮识别代码。详细结果见工作区 doc/2026-10-12-guomi-generalization.md。

## 2026-10-12 大数方程、辅助函数与指令覆盖补充

`bignum.py` 统一 OpenSSL BN、wolfSSL/LibTomMath mp/sp 和 mbedTLS MPI 的参数顺序，用有界多项式分式追踪加减乘、求逆、单独模约减及复制。签名要求绑定 `r=e+x (mod n)` 与 `s*(1+d)=k-r*d (mod n)`，允许乘法盲化的精确约分；验签要求绑定 `t=r+s`、`Q=sG+tP`、同一组合点的仿射横坐标及最终比较。OpenSSL Montgomery 操作保留转换比例 R，并绑定实际 group/order/mont accessor；不会直接当作普通乘法。不同模数、错误方程、未识别的值修改和本地同名 API 定义会阻断证据。只证明成功运算路径上的静态关系，没有完整控制流可行性或类型证明。

`binary_bignum.py` 在 x86-64 SysV/AArch64 ELF 中从未定义导入的重定位及 PLT/GOT 恢复通用数学调用和 ABI 参数，支持尾调用；算法函数定义名不参与识别。完全静态、全部大数原语也没有符号的未知实现，仍需新增原语识别。SM2 大数方程目前不覆盖 ARM/Thumb/MIPS/PE 的 ABI，也不是任意椭圆曲线机器码反编译器。

SM3/SM4 指令提升器会按实际代码推导小型本地辅助函数的返回值，最多 4 层、单次 192 条指令、合计 12,000 条辅助指令。仅接受能处理的直线函数及明确的 Clang 陷阱检查边；其他分支、未识别调用或非帧内写入拒绝返回摘要。参数、返回值、调用位置及线性角色保留在报告中；不能按旋转辅助函数的名字推测行为。修正了读取表同时覆盖地址寄存器的地址时序、地址栈溢出恢复、AArch64 动态旋转/位域拼装和 Capstone 5 对带操作数 UD1 的截断解码。源码辅助函数展开深度与表达式树深度分别限制，支持更深的真实运算组合。

SM4 继续要求读取完整标准 S 盒/CK、相关 L/L-prime 或标准 T 表运算；另支持实际解码的 AArch64 SM4 轮和密钥指令组合。SM3 同时要求消息展开和两类轮指令，或原有 P0/P1/算术见证；本地辅助函数的运算可沿已核实的调用投影回压缩函数。较长检查构建仅在一个有界返回区间内合并 SM3 见证，不用全文件旋转直方图判定。x86 SM4 专用指令只在反汇编器确实解码时处理；当前 Capstone 5 对较新 ISA 的支持和基于 AES-NI/仿射变换的 SM4 仍有限。

新增开发对照位于 `samples/guomi-operations-20261012`，包含自写正确/错误方程、拆分辅助函数、真实 ISA 对照和原固定上游的新构建；自写对照不能算新独立上游实现。没有把这些文件加入源码或整函数指纹库。本轮冻结后的固定集复测单独保存至 `validation_set/guomi-operations-20261012`，原资料及历次结果保留，成绩与限制见工作区 `doc/2026-10-12-guomi-operation-coverage.md`。
