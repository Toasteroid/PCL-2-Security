"""Mermaid 图块加固（第二轮，终版脚本）。

1) 删除 %%{init: ...}%% 指令行：部分渲染器会「删掉指令行 + 顺带吞掉后续换行」，
   导致 `flowchart TD` 与首条语句被拼成一行，报
   Parse error: Expecting 'NEWLINE', 'SPACE', 'GRAPH', got 'ALPHA'；
2) 每条语句末尾补 ASCII 分号：分号是 flowchart 的合法语句分隔符，
   即使换行被吃掉，整图仍可解析；
3) 节点文本按 maxu=13 个全角宽重新断行：去掉自定义 wrappingWidth 后
   使用 mermaid 默认值（wrappingWidth 200px、字号 16px），
   13 个汉字≈208px 略超，因此取 12~13 之间、并对断点做语义优选。

断点优先级：句读后 > 虚词前 > 硬切（不切 ASCII 标识符、不留孤字）。
"""
import io
import re
import sys

SOFT1 = set("；、，：）」》」。· 　")
SOFT2 = set("/ ?&=→")            # 次选：URL / 箭头分隔
FUNC = set("和与及或在被把将对从于使让为而并且")   # 虚词前断行较自然
LEAD = set(".,:;)]}/\\-_")       # 不该出现在行首的符号（属于上一段 token）


def bad_cut(seg, cut):
    """cut 是否落在不可切分的位置（ASCII 标识符/域名/路径中间）。"""
    if cut <= 0 or cut >= len(seg):
        return False
    a, b = seg[cut - 1], seg[cut]
    if b in LEAD and (a.isascii() and (a.isalnum() or a in "._-/")):
        return True
    if a.isascii() and b.isascii() and (a.isalnum() or a in "._-/") and (b.isalnum() or b in "._-/"):
        return True
    return False


def cw(c):
    return 1.0 if ord(c) > 0x1100 else 0.54


def width(s):
    return sum(cw(c) for c in s)


CLING = set("；、，：）」》」。,.;:/")     # 不应出现在行首的标点（并入上一行）
NOBREAK_AFTER = set("不没别很更最都也就还只才太再又可会要需该必能")


def _cands(raw, start, end, maxu):
    """行内候选断点：(位置, 优先级)，0=句读后 1=符号后 2=虚词前。"""
    out = []
    for j in range(start, end):
        if bad_cut(raw, j + 1):
            continue
        w = width(raw[start:j + 1])
        if raw[j] in SOFT1 and w >= maxu * 0.25:
            out.append((j + 1, 0))
        elif raw[j] in SOFT2 and w >= maxu * 0.50:
            out.append((j + 1, 1))
    for j in range(start + 1, end):
        if raw[j] in FUNC and not bad_cut(raw, j) and width(raw[start:j]) >= maxu * 0.30:
            if raw[j - 1] in NOBREAK_AFTER:      # 「不/在」「没/被」这类组合不拆
                continue
            out.append((j, 2))
    return out


def wrap(text, maxu=12.0):
    """整段重新断行（已有的 <br/> 会被吸收后重算），行宽 <= maxu 个全角。"""
    raw = text.replace("<br/>", "")
    out = []
    n = len(raw)
    start = 0
    while start < n:
        while start < n and raw[start] == " ":
            start += 1
        if start >= n:
            break
        end, cur = start, 0.0
        while end < n and cur + cw(raw[end]) <= maxu:
            cur += cw(raw[end])
            end += 1
        if end >= n:
            out.append(raw[start:].strip())
            break
        cands = _cands(raw, start, end, maxu)
        if cands:
            cut = None
            for pos, _pri in sorted(cands, key=lambda x: -x[0]):
                if width(raw[pos:]) >= maxu * 0.30 and width(raw[start:pos]) >= maxu * 0.30:
                    cut = pos
                    break
            if cut is None:
                cut = sorted(cands, key=lambda x: (x[1], -x[0]))[0][0]
        else:
            cut = end
            while cut < n and bad_cut(raw, cut):
                cut += 1
        if cut >= n:                       # 已吃到结尾，整段收尾
            out.append(raw[start:].strip())
            break
        # 回撤断点：避免只剩 1 个字（孤字）
        while cut > start + 1 and width(raw[cut:]) < 2.0:
            cut -= 1
        # 标点并入上一行，避免行首出现标点/孤立箭头
        while cut < n and raw[cut] in CLING:
            cut += 1
        if cut <= start:
            cut = end
        out.append(raw[start:cut].strip())
        start = cut
    return "<br/>".join([x for x in out if x])


LABEL_RE = re.compile(r'(\[|\{|\()"([^"]*)"(\]|\}|\))')
EDGE_RE = re.compile(r"\|([^|\n\"]+)\|")
MAXU = 12.5


def process(text: str) -> str:
    lines = text.split("\n")
    out, in_mm = [], False
    stats = {"directive": 0, "semi": 0, "label": 0, "edge": 0}
    for ln in lines:
        if ln.strip().startswith("```mermaid"):
            in_mm = True
            out.append(ln)
            continue
        if in_mm and ln.strip().startswith("```"):
            in_mm = False
            out.append(ln)
            continue
        if not in_mm:
            out.append(ln)
            continue
        s = ln.strip()
        if not s:
            out.append("")
            continue
        if s.startswith("%%"):
            stats["directive"] += 1
            continue
        new = LABEL_RE.sub(lambda m: m.group(1) + '"' + wrap(m.group(2), MAXU) + '"' + m.group(3), ln)
        if new != ln:
            stats["label"] += 1
        new2 = EDGE_RE.sub(lambda m: "|" + wrap(m.group(1), 12.0) + "|", new)
        if new2 != new:
            stats["edge"] += 1
        if not new2.rstrip().endswith(";"):
            new2 = new2.rstrip() + ";"
            stats["semi"] += 1
        out.append(new2)
    print(stats, file=sys.stderr)
    return "\n".join(out)


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    t = io.open(src, encoding="utf-8").read()
    io.open(dst, "w", encoding="utf-8", newline="\n").write(process(t))
