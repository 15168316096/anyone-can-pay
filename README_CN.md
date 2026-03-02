# ckb-anyone-can-pay

CKB anyone-can-pay 锁脚本。

[RFC-0026: Anyone-Can-Pay Lock](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0026-anyone-can-pay/0026-anyone-can-pay.md) | [RFC 草案讨论](https://talk.nervos.org/t/rfc-anyone-can-pay-lock/4438)

## 构建

``` sh
make all-via-docker && cargo test
```

## 快速开始

### 创建

1、创建一个可接收 UDT 和 CKB 的 cell：

```
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash>
    }
    data: <UDT amount>
    type: <UDT>
}
```

2、创建一个仅接收 CKB 的 cell：

```
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash>
    }
    data: <空>
    type: <无>
}
```

3、可以添加最低转账金额条件：

```
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash> | <最低 CKB> | <最低 UDT>
    }
    data: <UDT amount>
    type: <UDT>
}
```

`最低 CKB` 和 `最低 UDT` 是两个可选参数，各占一个字节，表示 `10 ^ x` 的最低金额。默认值为 `0`，表示任何人可以转入任意金额。转账必须满足 `最低 CKB` **或** `最低 UDT` 条件之一（OR 逻辑，符合 [RFC-0026 规则 2.g](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0026-anyone-can-pay/0026-anyone-can-pay.md) 的规定）。

如果所有者只想接收 `UDT`，可以将 `最低 CKB` 设置为 `255`。

### 发送 UDT 和 CKB

要向 anyone-can-pay 锁的 cell 转入代币，发送方必须构建一个与输入 anyone-can-pay cell 具有相同 `lock_hash` 和 `type_hash` 的输出 cell；如果输入 anyone-can-pay cell 没有 `data`，输出 cell 也必须为空。

```
# 输入
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash> | <最低 CKB: 2>
    }
    data: <空>
    type: <无>
    capacity: 100
}
...

# 输出
Cell {
    lock: {
        code_hash: <any-one-can-pay>
        args: <pubkey hash> | <最低 CKB: 2>
    }
    data: <空>
    type: <无>
    capacity: 200
}
...
```

### 签名解锁

所有者可以提供 secp256k1 签名来解锁 cell，签名方式与 [P2PH](https://github.com/nervosnetwork/ckb-system-scripts/wiki/How-to-sign-transaction#p2ph) 相同。

使用签名解锁 cell 没有任何限制，所有者可以自由管理其 cell。

## 安全审计

本仓库包含针对 [RFC-0026](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0026-anyone-can-pay/0026-anyone-can-pay.md) 规范的安全审计报告：

- [安全审计报告](SECURITY_AUDIT_REPORT.md) — 完整审计报告，含 RFC-0026 逐条合规性分析
- [审计检查清单](SECURITY_AUDIT_TODO.md) — 30 项审计检查项及其结果
