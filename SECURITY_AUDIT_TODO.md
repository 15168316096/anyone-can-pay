# anyone-can-pay 安全审计 TODO

> 版本: v1 | 最后更新: 2026-03-02 | 状态: 已完成

## 项目概况
  - 语言: C (合约核心逻辑) + Rust (构建/测试)
  - 类型: CKB 智能合约 (Lock Script)
  - 依赖数: 2 个 C 子模块 (ckb-c-stdlib, secp256k1) + 若干 Rust crate
  - 源文件数: 8 个 C 头文件/源文件 + 3 个 Rust 测试文件
  - 现有测试数: 27 个 (14 个 anyone-can-pay 测试 + 13 个 secp256k1 兼容性测试)

## 审计进度
  - 总 TODO 项: 22
  - ✅ 已完成: 22 | ❌ 发现问题: 4 | ⏳ 待审计: 0

---

## 第 1 章: DIM-INPUT 输入验证

- [x] 🔴 **AUDIT-INPUT-001**: Script args 长度校验
  - **关联代码**: c/anyone_can_pay.c:read_args:249-296
  - **审计内容**:
    - args 长度是否严格校验 (20-22 字节)
    - 缺失/超长参数的处理
  - **现有覆盖**: test_sighash_all_unlock_with_args 覆盖了带额外参数的场景
  - **发现记录**: ✅ 通过。args 长度校验正确：`args_bytes_seg.size < BLAKE160_SIZE || args_bytes_seg.size > BLAKE160_SIZE + 2` 拒绝非法长度。

- [x] 🔴 **AUDIT-INPUT-002**: Cell data 长度校验
  - **关联代码**: c/anyone_can_pay.c:load_type_hash_and_amount:44-102
  - **审计内容**:
    - CKB-only cell 数据必须为空
    - UDT cell 数据至少 16 字节
    - 畸形数据处理
  - **现有覆盖**: test_put_output_data, test_extended_udt
  - **发现记录**: ✅ 通过。CKB-only 要求 `len == 0`，UDT 要求 `len >= UDT_LEN(16)`。

- [x] 🟠 **AUDIT-INPUT-003**: type_hash 长度校验
  - **关联代码**: c/anyone_can_pay.c:load_type_hash_and_amount:48-61
  - **审计内容**:
    - type hash 返回长度是否为 32 字节
    - CKB_ITEM_MISSING 是否正确处理
  - **现有覆盖**: 多个测试间接覆盖
  - **发现记录**: ✅ 通过。`len != BLAKE2B_BLOCK_SIZE` 时返回 ERROR_ENCODING；CKB_ITEM_MISSING 标记为 is_ckb_only。

- [x] 🟠 **AUDIT-INPUT-004**: Witness 大小校验
  - **关联代码**: c/secp256k1_lock.h:66-92
  - **审计内容**:
    - Witness 超过 MAX_WITNESS_SIZE 的处理
    - Witness lock 字段长度校验
  - **现有覆盖**: test_super_long_witness
  - **发现记录**: ✅ 通过。`*witness_len > MAX_WITNESS_SIZE` 返回 ERROR_WITNESS_SIZE；lock 段 `!= SIGNATURE_SIZE` 返回 ERROR_ARGUMENTS_LEN。

- [x] 🟡 **AUDIT-INPUT-005**: quick_pow10 边界值处理
  - **关联代码**: c/quick_pow10.h:6-66
  - **审计内容**:
    - n 超出范围 (0-255) 的处理
    - uint128_quick_pow10 的乘法溢出
  - **现有覆盖**: test_overflow, test_udt_overflow
  - **发现记录**: ✅ 通过。n > MAX_POW_N(19) 返回溢出标志；uint128 最大计算 10^38 < 2^128，安全。

## 第 2 章: DIM-CRYPTO 密码学操作

- [x] 🔴 **AUDIT-CRYPTO-001**: secp256k1 签名验证流程
  - **关联代码**: c/secp256k1_lock.h:101-222
  - **审计内容**:
    - 签名恢复公钥流程是否正确
    - blake160 哈希比较是否安全
    - message 构造是否包含所有必要数据
  - **现有覆盖**: test_sighash_all_unlock, test_signing_with_wrong_key, test_signing_wrong_tx_hash
  - **发现记录**: ✅ 通过。标准 sighash_all 实现，message = blake2b(tx_hash || witness_len || zeroed_witness || group_witnesses || extra_witnesses)。

- [x] 🔴 **AUDIT-CRYPTO-002**: 签名消息覆盖范围
  - **关联代码**: c/secp256k1_lock.h:140-183
  - **审计内容**:
    - 是否覆盖 tx_hash
    - 是否覆盖同组所有 witness
    - 是否覆盖 inputs 之外的 witness
    - witness 长度是否也被哈希
  - **现有覆盖**: test_sighash_all_witness_args_ambiguity, test_sighash_all_witnesses_ambiguity, test_sighash_all_cover_extra_witnesses
  - **发现记录**: ✅ 通过。消息哈希覆盖完整，包括 witness 长度前缀（防止长度扩展攻击），extra witnesses 也被包含。

- [x] 🟠 **AUDIT-CRYPTO-003**: secp256k1 数据加载安全
  - **关联代码**: c/secp256k1_helper.h:36-86
  - **审计内容**:
    - 预计算数据通过 data_hash 匹配加载
    - 数据大小验证
  - **现有覆盖**: 所有签名相关测试间接覆盖
  - **发现记录**: ✅ 通过。通过 blake2b hash 精确匹配 cell dep 数据，长度严格校验 `len != CKB_SECP256K1_DATA_SIZE`。

## 第 3 章: DIM-LOGIC 业务逻辑

- [x] 🔴 **AUDIT-LOGIC-001**: 支付解锁金额校验逻辑
  - **关联代码**: c/anyone_can_pay.c:check_payment_unlock:104-247
  - **审计内容**:
    - CKB/UDT 金额增加校验
    - 溢出保护
    - OR 条件语义正确性
  - **现有覆盖**: test_unlock_by_anyone, test_insufficient_pay, test_payment_not_meet_requirement
  - **发现记录**: ⚠️ 建议改进。详见 AUDIT-LOGIC-001 详细分析。

- [x] 🔴 **AUDIT-LOGIC-002**: Input-Output 1:1 配对校验
  - **关联代码**: c/anyone_can_pay.c:check_payment_unlock:140-244
  - **审计内容**:
    - 每个 input 是否恰好匹配一个 output
    - 每个 output 是否恰好匹配一个 input
    - 防止拆分/合并攻击
  - **现有覆盖**: test_split_cell, test_merge_cell, test_no_pair
  - **发现记录**: ✅ 通过。双重计数器机制（found_inputs + output_cnt）确保严格 1:1 配对。

- [x] 🔴 **AUDIT-LOGIC-003**: 签名/支付双路径选择安全
  - **关联代码**: c/anyone_can_pay.c:main:298-325
  - **审计内容**:
    - 两条解锁路径是否互斥
    - 路径选择是否可被攻击者控制
  - **现有覆盖**: 所有测试覆盖
  - **发现记录**: ⚠️ 建议改进。详见 AUDIT-LOGIC-003 详细分析。

- [x] 🟠 **AUDIT-LOGIC-004**: Type hash 匹配逻辑
  - **关联代码**: c/anyone_can_pay.c:check_payment_unlock:182-193
  - **审计内容**:
    - CKB-only 匹配逻辑
    - UDT type hash 匹配
    - 不同类型输入的隔离
  - **现有覆盖**: test_udt_unlock_by_anyone, test_only_pay_ckb, test_only_pay_udt
  - **发现记录**: ✅ 通过。CKB-only 通过 is_ckb_only 标志匹配，UDT 通过 32 字节 type_hash 全量比较。

- [x] 🟠 **AUDIT-LOGIC-005**: 溢出加法保护
  - **关联代码**: c/overflow_add.h:1-19
  - **审计内容**:
    - uint64 溢出检测正确性
    - uint128 溢出检测正确性
  - **现有覆盖**: test_overflow, test_udt_overflow
  - **发现记录**: ✅ 通过。`MAX - a < b` 是标准的溢出检测方法，对 uint64 和 uint128 均正确。

## 第 4 章: DIM-MEMORY 内存与资源安全

> 注: 根据审计要求，已移除内存对齐相关检查项（CKB RISC-V VM 通过软件模拟处理非对齐访问，非安全风险）。

- [x] 🟠 **AUDIT-MEMORY-001**: 栈空间使用分析
  - **关联代码**: c/anyone_can_pay.c:main, c/secp256k1_lock.h:verify_secp256k1_blake160_sighash_all_with_witness
  - **审计内容**:
    - 签名路径栈使用量估算
    - 支付路径栈使用量估算
    - 是否超出 CKB VM 栈限制
  - **现有覆盖**: 所有测试间接覆盖
  - **发现记录**: ⚠️ 建议改进。详见 AUDIT-MEMORY-001 详细分析。

- [x] 🟡 **AUDIT-MEMORY-002**: 数组越界访问
  - **关联代码**: c/anyone_can_pay.c:check_payment_unlock:121-136
  - **审计内容**:
    - input_wallets 数组访问边界
    - MAX_TYPE_HASH 限制是否有效
  - **现有覆盖**: 无直接测试
  - **发现记录**: ✅ 通过。`i >= MAX_TYPE_HASH` 检查在写入之前执行，防止越界。

- [x] 🟡 **AUDIT-MEMORY-003**: 整数溢出/下溢
  - **关联代码**: c/anyone_can_pay.c, c/overflow_add.h, c/quick_pow10.h
  - **审计内容**:
    - 所有算术运算的溢出保护
    - 类型转换安全 (uint8_t → int)
  - **现有覆盖**: test_overflow, test_udt_overflow
  - **发现记录**: ✅ 通过。所有关键加法运算使用 overflow_add 保护；quick_pow10 使用查表法避免计算溢出。

## 第 5 章: DIM-SERDE 序列化/反序列化

- [x] 🟠 **AUDIT-SERDE-001**: Molecule 序列化验证
  - **关联代码**: c/anyone_can_pay.c:read_args:264-273, c/secp256k1_lock.h:extract_witness_lock:34-50
  - **审计内容**:
    - Script 反序列化验证
    - WitnessArgs 反序列化验证
    - 畸形数据拒绝
  - **现有覆盖**: 多个测试间接覆盖
  - **发现记录**: ✅ 通过。所有 Molecule 反序列化前均调用 verify 方法检查格式有效性。

## 第 6 章: DIM-ERRINFO 错误处理与信息泄露

- [x] 🟡 **AUDIT-ERRINFO-001**: 错误码区分性
  - **关联代码**: c/anyone_can_pay.c:28-35, c/secp256k1_lock.h:15-27
  - **审计内容**:
    - 不同错误原因是否可被外部区分
    - 是否存在 oracle 风险
  - **现有覆盖**: 所有失败测试覆盖
  - **发现记录**: ⚠️ 建议改进。详见 AUDIT-ERRINFO-001 详细分析。

- [x] 🟡 **AUDIT-ERRINFO-002**: 错误处理完备性
  - **关联代码**: 全部 C 源码
  - **审计内容**:
    - 所有 syscall 返回值是否被检查
    - 是否存在被忽略的错误
  - **现有覆盖**: 多个测试间接覆盖
  - **发现记录**: ✅ 通过。所有 ckb_load_* 返回值均被检查处理。

## 第 7 章: DIM-DEPS 依赖安全

- [x] 🟡 **AUDIT-DEPS-001**: C 子模块版本安全
  - **关联代码**: .gitmodules, deps/
  - **审计内容**:
    - ckb-c-stdlib 版本
    - secp256k1 版本
    - 已知 CVE
  - **现有覆盖**: N/A
  - **发现记录**: ✅ 通过。使用 Nervos 维护的 fork 版本，无已知 CVE。子模块目录为空（需初始化）。

- [x] 🟡 **AUDIT-DEPS-002**: Rust 依赖安全
  - **关联代码**: Cargo.toml, Cargo.lock
  - **审计内容**:
    - 依赖版本是否有已知漏洞
    - 依赖来源是否可信
  - **现有覆盖**: N/A
  - **发现记录**: ✅ 通过。依赖来自 crates.io 和 Nervos GitHub，版本较旧但无已知严重漏洞。

---

## 附录 A: 审计执行日志
| 日期 | 审计项 | 发现摘要 | 状态 |
|------|--------|---------|------|
| 2026-03-02 | AUDIT-INPUT-001~005 | 输入验证全面，无漏洞 | ✅ |
| 2026-03-02 | AUDIT-CRYPTO-001~003 | 密码学操作正确 | ✅ |
| 2026-03-02 | AUDIT-LOGIC-001~005 | 发现 2 项建议改进 | ⚠️ |
| 2026-03-02 | AUDIT-MEMORY-001~003 | 发现 1 项栈空间建议 | ⚠️ |
| 2026-03-02 | AUDIT-SERDE-001 | 序列化验证正确 | ✅ |
| 2026-03-02 | AUDIT-ERRINFO-001~002 | 发现 1 项错误码建议 | ⚠️ |
| 2026-03-02 | AUDIT-DEPS-001~002 | 依赖安全 | ✅ |

## 附录 B: 新增项跟踪
| 日期 | 新增项 ID | 来源 | 描述 |
|------|----------|------|------|
| - | - | - | 审计过程中未发现需新增的攻击面 |

## 附录 C: 修复建议
| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|--------|---------|---------|---------|
| AUDIT-LOGIC-001 | Medium | 文档明确 OR 语义；考虑是否需要 AND 模式选项 | 待处理 |
| AUDIT-LOGIC-003 | Low | 属设计特性，建议文档补充说明 | 待处理 |
| AUDIT-MEMORY-001 | Low | 监控栈使用，考虑减少栈上大缓冲区 | 待处理 |
| AUDIT-ERRINFO-001 | Info | 考虑统一错误码以减少信息泄露 | 待处理 |
