# 安全审计报告: anyone-can-pay (CKB Lock Script)

## 1. 执行摘要

### 项目信息
| 项目 | 详情 |
|------|------|
| 项目名称 | anyone-can-pay |
| 仓库地址 | https://github.com/15168316096/anyone-can-pay |
| 语言 | C (合约核心) + Rust (构建/测试) |
| 项目类型 | CKB 链上 Lock Script（智能合约） |
| 编译目标 | RISC-V 64 (riscv64-unknown-linux-gnu) |
| 审计日期 | 2026-03-02 |
| 审计方法 | AI 辅助静态分析 + 人工代码审查 |
| 审计范围 | 全部 C 源码（8 文件）、Rust 测试代码（3 文件）、构建配置 |

### 项目描述

anyone-can-pay 是 CKB（Nervos Network）上的一个 Lock Script，实现了"任何人均可支付"的功能。该脚本允许两种解锁方式：

1. **签名解锁**：所有者通过 secp256k1 签名解锁，无任何限制
2. **支付解锁**：任何人无需签名即可解锁，但必须在输出中创建一个相同 lock hash 和 type hash 的 cell，且金额不减少（满足最低增加量要求）

### 关键数字
| 指标 | 数值 |
|------|------|
| C 源文件 | 8 个 (`.c` + `.h`) |
| 核心逻辑代码 | ~325 行 (anyone_can_pay.c) + ~224 行 (secp256k1_lock.h) |
| 测试用例 | 27 个 (14 ACP + 13 secp256k1) |
| 审计项 | 22 个 |
| 发现问题 | 4 项 (0 Critical, 0 High, 1 Medium, 2 Low, 1 Info) |

### 审计特别说明
> **已移除内存对齐检查项**：根据审计要求，CKB RISC-V VM 通过软件模拟处理非对齐内存访问，内存对齐不构成安全风险，故本次审计中移除了所有内存对齐相关的检查项。

---

## 2. 风险评级

| 级别 | 数量 | 说明 |
|------|------|------|
| 🔴 Critical | 0 | 无需立即修复的严重漏洞 |
| 🟠 High | 0 | 无高风险问题 |
| 🟡 Medium | 1 | 业务逻辑设计需关注 |
| 🟢 Low | 2 | 改进建议 |
| ℹ️ Info | 1 | 信息性建议 |

**整体评价：该合约代码质量较高，核心逻辑清晰，安全防护措施完善。未发现可直接利用的严重安全漏洞。以下发现主要为设计层面的建议和潜在风险提示。**

---

## 3. 关键发现（按严重级别降序）

---

### FINDING-001: 支付解锁的 OR 条件语义可能导致用户误解

| 属性 | 详情 |
|------|------|
| **ID** | FINDING-001 |
| **严重级别** | 🟡 Medium |
| **类型** | 业务逻辑 |
| **影响范围** | 支付路径解锁逻辑 |
| **关联审计项** | AUDIT-LOGIC-001 |

#### 描述

`check_payment_unlock` 函数中，最低 CKB 金额和最低 UDT 金额的校验使用 OR 逻辑（满足其一即可）。这意味着：

- 设置了 `min_ckb_amount = 100` 和 `min_udt_amount = 50` 的 cell
- 攻击者只需转入 100 CKB **或** 50 UDT 即可解锁
- **不需要同时满足两个条件**

虽然该逻辑包含了防盗保护（未满足条件的币种金额必须保持不变），但 OR 语义可能与用户（cell 所有者）的预期不符。

#### 关键代码引用

```c
// c/anyone_can_pay.c:196-214
uint64_t min_output_ckb_amount = 0;
uint128_t min_output_udt_amount = 0;
int overflow = 0;
overflow = uint64_overflow_add(
    &min_output_ckb_amount, input_wallets[j].ckb_amount, min_ckb_amount);
int meet_ckb_cond = !overflow && ckb_amount >= min_output_ckb_amount;
overflow = uint128_overflow_add(
    &min_output_udt_amount, input_wallets[j].udt_amount, min_udt_amount);
int meet_udt_cond = !overflow && udt_amount >= min_output_udt_amount;

/* fail if can't meet both conditions */  // ← 注释有误，实际是 "any" 不是 "both"
if (!(meet_ckb_cond || meet_udt_cond)) {
    return ERROR_OUTPUT_AMOUNT_NOT_ENOUGH;
}
/* output coins must meet condition, or remain the old amount */
if ((!meet_ckb_cond && ckb_amount != input_wallets[j].ckb_amount) ||
    (!meet_udt_cond && udt_amount != input_wallets[j].udt_amount)) {
    return ERROR_OUTPUT_AMOUNT_NOT_ENOUGH;
}
```

#### 分析过程

**正向逻辑审查：**
1. 当 `meet_ckb_cond = true, meet_udt_cond = false` 时：
   - CKB 增加量满足要求 ✓
   - UDT 金额必须与输入完全相同（`udt_amount == input_wallets[j].udt_amount`）✓
   - → 不会丢失 UDT
2. 当 `meet_ckb_cond = false, meet_udt_cond = true` 时：
   - UDT 增加量满足要求 ✓
   - CKB 金额必须与输入完全相同 ✓
   - → 不会丢失 CKB
3. 当两者都满足时：两种币都增加了 ✓

**逆向攻击思维：**
- ❌ 尝试偷取 CKB：输出 CKB < 输入 CKB → 即使 UDT 满足条件，CKB 必须保持不变 → 失败
- ❌ 尝试偷取 UDT：输出 UDT < 输入 UDT → 即使 CKB 满足条件，UDT 必须保持不变 → 失败
- ✅ 防盗保护有效

**结论：该逻辑不存在直接的资金安全风险，但 OR 语义可能与部分用户的 AND 预期不符。代码中注释 `fail if can't meet both conditions` 与实际逻辑不一致。**

#### 修复建议

1. **[建议]** 修正代码注释：将 `fail if can't meet both conditions` 改为 `fail if can't meet either condition`
2. **[建议]** 在 README 中更明确地说明 OR 语义及其安全含义
3. **[可选]** 考虑在未来版本中增加 AND 模式选项（通过 args 中的额外标志位控制）

---

### FINDING-002: 签名/支付路径选择基于 witness 格式，可被外部控制

| 属性 | 详情 |
|------|------|
| **ID** | FINDING-002 |
| **严重级别** | 🟢 Low |
| **类型** | 业务逻辑 / 路径控制 |
| **影响范围** | 解锁路径选择 |
| **关联审计项** | AUDIT-LOGIC-003 |

#### 描述

合约通过检测第一个 witness 是否为有效的 `WitnessArgs` 且 lock 字段长度为 65 字节（SIGNATURE_SIZE）来决定走签名路径还是支付路径。攻击者可以通过控制 witness 格式来选择解锁路径。

#### 关键代码引用

```c
// c/anyone_can_pay.c:main:309-324
ret = load_secp256k1_first_witness_and_check_signature(first_witness,
                                                        &first_witness_len);
int has_sig = ret == CKB_SUCCESS;

/* ACP verification */
if (has_sig) {
    /* unlock via signature */
    return verify_secp256k1_blake160_sighash_all_with_witness(
        pubkey_hash, first_witness, first_witness_len);
} else {
    /* unlock via payment */
    return check_payment_unlock(min_ckb_amount, min_udt_amount);
}
```

#### 分析过程

**攻击场景 1**：攻击者提供无效 witness → `has_sig = false` → 进入支付路径
- 支付路径有独立的金额校验，不存在绕过风险
- 攻击者仍必须满足所有支付条件

**攻击场景 2**：攻击者提供格式正确但签名无效的 witness → `has_sig = true` → 进入签名路径
- 签名验证失败，交易被拒绝
- 无安全风险

**攻击场景 3**：所有者想通过签名解锁但 witness 被篡改
- CKB 交易中 witness 由交易构造者控制
- 如果所有者自己构造交易，witness 不会被篡改
- 如果通过第三方构造交易，witness 可能被修改，但这本身就是不可信场景

**结论：路径选择虽可被外部控制，但两条路径各自有完整的安全保护，不存在通过路径切换绕过安全检查的可能性。此为设计特性而非漏洞。**

#### 修复建议

1. **[建议]** 在文档中明确说明路径选择机制
2. **[信息]** 此为已知设计决策，无需代码修改

---

### FINDING-003: 签名路径栈空间使用量较大

| 属性 | 详情 |
|------|------|
| **ID** | FINDING-003 |
| **严重级别** | 🟢 Low |
| **类型** | 资源使用 |
| **影响范围** | 签名验证路径 |
| **关联审计项** | AUDIT-MEMORY-001 |

#### 描述

合约在签名验证路径中使用了较大的栈空间：

| 函数 | 变量 | 大小 |
|------|------|------|
| `main()` | `first_witness[MAX_WITNESS_SIZE]` | 32 KB |
| `main()` | `pubkey_hash`, `min_amounts` | ~44 B |
| `verify_secp256k1_...()` | `temp[MAX_WITNESS_SIZE]` | 32 KB |
| `verify_secp256k1_...()` | `lock_bytes[SIGNATURE_SIZE]` | 65 B |
| `verify_secp256k1_...()` | `secp_data[CKB_SECP256K1_DATA_SIZE]` | ~1.2 MB |
| `verify_secp256k1_...()` | `blake2b_ctx`, 其他 | ~500 B |
| **签名路径总计** | | **~1.26 MB** |

支付路径栈使用较小：

| 函数 | 变量 | 大小 |
|------|------|------|
| `main()` | `first_witness[MAX_WITNESS_SIZE]` | 32 KB |
| `check_payment_unlock()` | `input_wallets[MAX_TYPE_HASH]` | ~15 KB |
| `check_payment_unlock()` | 循环内局部变量 | ~100 B |
| **支付路径总计** | | **~47 KB** |

CKB VM 默认栈空间为 4 MB，当前使用量在安全范围内，但签名路径的 ~1.26 MB 占比约 31%。

#### 修复建议

1. **[可选]** 考虑将 `secp_data` 通过 `mmap` 或其他方式加载而非栈上分配（需 CKB VM 支持）
2. **[信息]** 当前使用量在安全范围内，仅为提示

---

### FINDING-004: 差异化错误码可能泄露合约内部状态

| 属性 | 详情 |
|------|------|
| **ID** | FINDING-004 |
| **严重级别** | ℹ️ Info |
| **类型** | 信息泄露 |
| **影响范围** | 错误处理 |
| **关联审计项** | AUDIT-ERRINFO-001 |

#### 描述

合约使用了多个不同的错误码（-1 到 -46），外部观察者可以通过交易执行返回的错误码推断合约内部状态：

```c
// secp256k1 相关
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_VERIFICATION -12
...

// anyone-can-pay 相关
#define ERROR_OVERFLOW -41
#define ERROR_OUTPUT_AMOUNT_NOT_ENOUGH -42
#define ERROR_TOO_MUCH_TYPE_HASH_INPUTS -43
#define ERROR_NO_PAIR -44
#define ERROR_DUPLICATED_INPUTS -45
#define ERROR_DUPLICATED_OUTPUTS -46
```

例如，攻击者可以区分：
- `-44 (ERROR_NO_PAIR)`：没有匹配的输出 cell
- `-42 (ERROR_OUTPUT_AMOUNT_NOT_ENOUGH)`：金额不足
- `-45 (ERROR_DUPLICATED_INPUTS)`：尝试合并 cell

#### 分析过程

在 CKB 生态中，Lock Script 的执行结果（包括错误码）是公开可见的。差异化错误码可以帮助攻击者了解交易失败的具体原因，但由于：

1. CKB 交易本身是公开的，攻击者可以自行模拟执行
2. 错误码不暴露任何密钥/签名相关的私密信息
3. 差异化错误码有助于用户调试交易

因此，信息泄露风险极低。

#### 修复建议

1. **[信息]** 当前设计合理，错误码有助于调试，无需修改
2. **[可选]** 如果需要更强隐私保护，可以将所有非签名错误合并为一个通用错误码

---

## 4. 审计覆盖矩阵

### 函数/模块 × 审计维度

| 函数/模块 | 输入验证 | 密码学 | 业务逻辑 | 内存安全 | 序列化 | 错误处理 |
|-----------|---------|--------|---------|---------|--------|---------|
| `main()` | ✅ | - | ✅ | ✅ | - | ✅ |
| `read_args()` | ✅ | - | ✅ | ✅ | ✅ | ✅ |
| `load_type_hash_and_amount()` | ✅ | - | ✅ | ✅ | - | ✅ |
| `check_payment_unlock()` | ✅ | - | ✅ ⚠️ | ✅ | - | ✅ ⚠️ |
| `extract_witness_lock()` | ✅ | - | - | ✅ | ✅ | ✅ |
| `load_secp256k1_first_witness_and_check_signature()` | ✅ | ✅ | ✅ ⚠️ | ✅ | ✅ | ✅ |
| `verify_secp256k1_blake160_sighash_all_with_witness()` | ✅ | ✅ | ✅ | ✅ ⚠️ | ✅ | ✅ |
| `uint64_overflow_add()` | - | - | ✅ | ✅ | - | - |
| `uint128_overflow_add()` | - | - | ✅ | ✅ | - | - |
| `quick_pow10()` | ✅ | - | ✅ | ✅ | - | - |
| `uint128_quick_pow10()` | ✅ | - | ✅ | ✅ | - | - |
| `ckb_secp256k1_custom_verify_only_initialize()` | ✅ | ✅ | - | ✅ | - | ✅ |

图例：✅ 已审计通过 | ⚠️ 已审计，有建议 | - 不适用

### 测试覆盖分析

| 功能模块 | 正常路径 | 错误路径 | 边界值 | 安全攻击 |
|----------|---------|---------|--------|---------|
| 签名解锁 | ✅ | ✅ | ✅ | ✅ |
| 支付解锁 (CKB) | ✅ | ✅ | ✅ | ⚠️ |
| 支付解锁 (UDT) | ✅ | ✅ | ✅ | ⚠️ |
| 最低金额限制 | ✅ | ✅ | ✅ | - |
| Cell 拆分防护 | - | ✅ | - | ✅ |
| Cell 合并防护 | - | ✅ | - | ✅ |
| 扩展 UDT 数据 | ✅ | - | - | - |

**测试覆盖盲区：**
1. ⚠️ 缺少多种不同 type hash 的 UDT cell 同时存在的测试
2. ⚠️ 缺少 CKB-only 和 UDT cell 混合存在的支付解锁测试
3. ⚠️ 缺少 MAX_TYPE_HASH (256) 边界的测试
4. ⚠️ 缺少 min_ckb_amount 和 min_udt_amount 同时设置的复合条件测试
5. ⚠️ 缺少对 `quick_pow10` 所有边界值 (0, 19, 20, 255) 的专项测试

---

## 5. 依赖安全状态

### C 依赖 (子模块)

| 依赖 | 来源 | 版本/状态 | 安全评估 |
|------|------|----------|---------|
| ckb-c-stdlib | nervosnetwork/ckb-c-stdlib | 子模块引用 | ✅ Nervos 官方维护 |
| secp256k1 | nervosnetwork/secp256k1 | 子模块引用 | ✅ Nervos 官方 fork，基于 Bitcoin Core |

### Rust 依赖 (构建/测试)

| 依赖 | 版本 | 用途 | 安全评估 |
|------|------|------|---------|
| ckb-types | 0.24.0-pre (git) | 测试 | ✅ 官方库 |
| ckb-script | 0.24.0-pre (git) | 测试 | ✅ 官方库 |
| ckb-crypto | 0.24.0-pre (git) | 测试 | ✅ 官方库 |
| secp256k1 | 0.15.1 | 测试 | ✅ |
| blake2b-rs | 0.1.5 | 构建 | ✅ |
| rand | 0.6.5 | 测试 | ✅ |
| includedir | 0.5.0 | 构建 | ✅ |

**注意：** 依赖版本普遍较旧（2019 年），建议定期更新以获取安全修复。但作为已部署的合约，更新需谨慎评估兼容性。

---

## 6. 改进建议（非漏洞类）

### 6.1 代码质量

1. **注释修正** — `check_payment_unlock` 中第 205 行注释 `fail if can't meet both conditions` 应改为 `fail if can't meet either condition`，以准确反映 OR 逻辑

2. **常量命名** — `MAX_TYPE_HASH` 名称可能造成误导，它实际表示"最大输入 wallet 数量"而非"最大 type hash 数量"。建议重命名为 `MAX_INPUT_WALLETS`

3. **函数文档** — 建议为 `check_payment_unlock` 和 `load_type_hash_and_amount` 添加函数级注释，说明前置条件、后置条件和错误返回值

### 6.2 测试完善

1. **增加复合条件测试** — 同时设置 `min_ckb_amount` 和 `min_udt_amount` 时的各种组合
2. **增加边界值测试** — MAX_TYPE_HASH 边界、quick_pow10 边界
3. **增加混合类型测试** — CKB-only 和 UDT cell 在同一交易中的交互
4. **增加模糊测试** — 对 args 解析和 witness 解析引入模糊测试

### 6.3 文档完善

1. **安全模型文档** — 建议添加专门的安全模型说明文档，阐述：
   - 信任边界定义
   - OR vs AND 语义的设计决策
   - 已知限制（如 MAX_TYPE_HASH）
   - 攻击面分析

---

## 7. 附录: 完整审计详情

### A. 架构与数据流

```
                    ┌─────────────────┐
                    │     main()      │
                    │  读取 script    │
                    │  args           │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   read_args()   │
                    │  解析 pubkey    │
                    │  hash + 最低   │
                    │  金额参数       │
                    └────────┬────────┘
                             │
              ┌──────────────▼───────────────┐
              │  load_secp256k1_first_       │
              │  witness_and_check_signature │
              │  检测是否有有效签名           │
              └──────────────┬───────────────┘
                             │
                    ┌────────▼────────┐
                    │   has_sig?      │
                    └───┬─────────┬───┘
                    YES │         │ NO
           ┌────────────▼─┐   ┌──▼──────────────┐
           │verify_secp256│   │check_payment_    │
           │k1_blake160_  │   │unlock()          │
           │sighash_all   │   │                  │
           │_with_witness │   │ 1. 加载所有 group │
           │              │   │    inputs        │
           │ 1. 提取签名  │   │ 2. 遍历所有      │
           │ 2. 计算消息  │   │    outputs       │
           │    hash      │   │ 3. 匹配 type     │
           │ 3. 恢复公钥  │   │    hash          │
           │ 4. 比较      │   │ 4. 校验金额      │
           │    blake160  │   │    增加量         │
           └──────────────┘   │ 5. 验证 1:1      │
                              │    配对           │
                              └──────────────────┘
```

### B. 信任边界

```
  ┌─────────────────────────────────────────────┐
  │              不可信输入                       │
  │                                             │
  │  ┌──────────┐  ┌──────────┐  ┌───────────┐ │
  │  │ Witness  │  │ Cell Data│  │ Script    │ │
  │  │ (签名/   │  │ (UDT    │  │ Args      │ │
  │  │  空数据)  │  │  金额)   │  │ (pubkey   │ │
  │  │          │  │          │  │  hash+    │ │
  │  │          │  │          │  │  最低金额) │ │
  │  └────┬─────┘  └────┬─────┘  └─────┬─────┘ │
  │       │             │              │        │
  └───────┼─────────────┼──────────────┼────────┘
          │             │              │
  ┌───────▼─────────────▼──────────────▼────────┐
  │           anyone-can-pay 合约                │
  │                                             │
  │  验证: 格式 → 长度 → 签名/金额 → 配对       │
  └─────────────────────────────────────────────┘
          │
  ┌───────▼──────────────────────────────────────┐
  │              可信数据                         │
  │                                              │
  │  ┌──────────┐  ┌──────────┐                  │
  │  │ TX Hash  │  │ secp256k1│                  │
  │  │ (CKB VM  │  │ precomp  │                  │
  │  │  提供)    │  │ data     │                  │
  │  │          │  │ (hash    │                  │
  │  │          │  │  verified)│                  │
  │  └──────────┘  └──────────┘                  │
  └──────────────────────────────────────────────┘
```

### C. 完整调用链分析

#### 签名解锁路径
```
main()
  ├── read_args()
  │     ├── ckb_load_script()           # 加载当前 script
  │     ├── MolReader_Script_verify()   # 验证 Molecule 格式
  │     ├── MolReader_Script_get_args() # 提取 args
  │     └── quick_pow10() / uint128_quick_pow10()  # 解析最低金额
  │
  ├── load_secp256k1_first_witness_and_check_signature()
  │     ├── ckb_load_witness()          # 加载第一个 group witness
  │     ├── extract_witness_lock()      # 提取 lock 字段
  │     │     ├── MolReader_WitnessArgs_verify()
  │     │     ├── MolReader_WitnessArgs_get_lock()
  │     │     └── MolReader_Bytes_raw_bytes()
  │     └── 检查 lock 长度 == SIGNATURE_SIZE
  │
  └── verify_secp256k1_blake160_sighash_all_with_witness()
        ├── extract_witness_lock()      # 再次提取（从副本）
        ├── ckb_load_tx_hash()          # 加载 tx hash
        ├── blake2b(tx_hash || witnesses)  # 计算签名消息
        │     ├── 清零 lock 字段
        │     ├── 哈希第一个 witness (含长度前缀)
        │     ├── 循环哈希同组其他 witnesses
        │     └── 循环哈希 inputs 之外的 witnesses
        ├── ckb_secp256k1_custom_verify_only_initialize()  # 初始化 secp256k1
        ├── secp256k1_ecdsa_recoverable_signature_parse_compact()  # 解析签名
        ├── secp256k1_ecdsa_recover()   # 恢复公钥
        ├── secp256k1_ec_pubkey_serialize()  # 序列化公钥
        └── blake2b(pubkey) → 比较前 20 字节  # 验证身份
```

#### 支付解锁路径
```
main()
  ├── read_args()  (同上)
  │
  ├── load_secp256k1_first_witness_and_check_signature()
  │     └── 返回非 CKB_SUCCESS (无有效签名)
  │
  └── check_payment_unlock()
        ├── ckb_load_script_hash()      # 获取当前 lock hash
        │
        ├── [循环] 加载所有 group inputs
        │     └── load_type_hash_and_amount()
        │           ├── ckb_checked_load_cell_by_field(TYPE_HASH)
        │           ├── ckb_checked_load_cell_by_field(CAPACITY)
        │           └── ckb_load_cell_data()  # UDT 金额
        │
        ├── [循环] 遍历所有 outputs
        │     ├── ckb_checked_load_cell_by_field(LOCK_HASH)
        │     ├── 比较 lock hash (跳过非 ACP 的)
        │     ├── load_type_hash_and_amount()  # 加载 output 信息
        │     └── [循环] 在 inputs 中查找匹配的 type hash
        │           ├── uint64_overflow_add()   # CKB 最低金额计算
        │           ├── uint128_overflow_add()  # UDT 最低金额计算
        │           ├── 校验金额条件 (OR 逻辑)
        │           └── 更新配对计数器
        │
        └── [循环] 验证所有 inputs 都有配对
              └── output_cnt == 1 检查
```

### D. 安全审计检查清单总结

| # | 检查项 | 结果 | 备注 |
|---|--------|------|------|
| 1 | Script args 解析安全 | ✅ PASS | 长度校验 20-22 字节 |
| 2 | Cell data 长度校验 | ✅ PASS | CKB-only 要求空，UDT 要求 ≥16 |
| 3 | Type hash 校验 | ✅ PASS | 32 字节全量比较 |
| 4 | Witness 格式校验 | ✅ PASS | Molecule verify + 长度校验 |
| 5 | 签名消息构造 | ✅ PASS | 标准 sighash_all，含长度前缀 |
| 6 | 公钥恢复与验证 | ✅ PASS | secp256k1 ECDSA 恢复 + blake160 |
| 7 | 支付金额校验 | ⚠️ NOTE | OR 逻辑，含防盗保护 |
| 8 | Input-Output 配对 | ✅ PASS | 严格 1:1 |
| 9 | 防拆分 | ✅ PASS | ERROR_DUPLICATED_OUTPUTS |
| 10 | 防合并 | ✅ PASS | ERROR_DUPLICATED_INPUTS |
| 11 | 整数溢出保护 | ✅ PASS | overflow_add 检测 |
| 12 | 数组越界保护 | ✅ PASS | MAX_TYPE_HASH 检查 |
| 13 | 栈空间使用 | ⚠️ NOTE | 签名路径约 1.26MB |
| 14 | Molecule 反序列化 | ✅ PASS | 均有 verify 校验 |
| 15 | 错误处理完备性 | ✅ PASS | 所有 syscall 返回值已检查 |
| 16 | 错误码信息泄露 | ℹ️ INFO | 风险极低 |
| 17 | secp256k1 数据加载 | ✅ PASS | Hash 验证 + 长度校验 |
| 18 | 依赖安全 | ✅ PASS | 无已知 CVE |
| 19 | 防重放 | ✅ PASS | tx_hash 绑定 |
| 20 | witness 歧义防护 | ✅ PASS | 有专项测试覆盖 |
| 21 | 路径选择安全 | ⚠️ NOTE | 可控但两路径均安全 |
| 22 | 最低金额溢出处理 | ✅ PASS | 溢出时设为 MAX 值 |

---

## 8. 审计结论

### 整体安全评估：**良好 (Good)**

anyone-can-pay 合约代码结构清晰，安全意识良好：

**优点：**
- ✅ 所有外部输入均有严格的格式和长度校验
- ✅ 整数运算有完善的溢出保护机制
- ✅ Input-Output 配对机制严格防止了拆分/合并攻击
- ✅ 签名验证遵循 CKB 标准 sighash_all 规范
- ✅ Molecule 序列化/反序列化均有格式验证
- ✅ 测试覆盖了主要的正常和异常路径
- ✅ 错误处理完备，无静默忽略的错误

**关注点：**
- ⚠️ CKB/UDT 最低金额的 OR 语义需要用户充分理解
- ⚠️ 签名路径栈使用量较大（但在 VM 限制内）
- ⚠️ 测试覆盖存在若干盲区（混合类型、边界值、复合条件）

**未发现可直接利用的安全漏洞。所有发现均为设计层面的建议或低风险提示。**

---

*本报告由 AI 辅助安全审计生成，建议结合人工审查和动态测试进行综合评估。*
