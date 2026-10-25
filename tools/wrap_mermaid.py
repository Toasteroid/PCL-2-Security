"""为 mermaid 节点文本按语义断行，避免渲染时右侧被截断。"""
import io, re, sys

SOFT1 = set("；、，：）】》」。，· 　")       # 首选断点：句读
SOFT2 = set("/ ?&=")                      # 次选断点：URL 分隔（不含 - _，避免切断标识符）
INIT = ('%%{init: {"flowchart": {"htmlLabels": true, "wrappingWidth": 240, '
        '"nodeSpacing": 30, "rankSpacing": 42}, '
        '"themeVariables": {"fontSize": "13px"}}}%%')


def cw(c):
    return 1.0 if ord(c) > 0x1100 else 0.55


def width(s):
    return sum(cw(c) for c in s)


def wrap(text, maxu=15.0):
    out = []
    for seg in text.split("<br/>"):
        seg = seg.strip()
        if not seg:
            continue
        start, n = 0, len(seg)
        while start < n:
            end, cur = start, 0.0
            while end < n and cur + cw(seg[end]) <= maxu:
                cur += cw(seg[end])
                end += 1
            if end >= n:
                out.append(seg[start:].strip())
                break
            if width(seg[end:]) <= maxu * 0.35:   # 尾巴太短，避免孤字成行
                out.append(seg[start:].strip())
                break
            cut, acc = -1, 0.0
            for j in range(start, end):
                acc += cw(seg[j])
                if seg[j] in SOFT1 and acc >= maxu * 0.40:
                    cut = j + 1
            if cut == -1:
                acc = 0.0
                for j in range(start, end):
                    acc += cw(seg[j])
                    if seg[j] in SOFT2 and acc >= maxu * 0.60:
                        cut = j + 1
            if cut == -1:
                cut = end
                while cut < n and seg[cut] in SOFT1 | SOFT2:
                    cut += 1
                # 不把 ASCII 标识符（如 PARSE-001）从中间切开
                while (cut < n and cut > start + 1
                       and seg[cut - 1].isascii() and seg[cut - 1].isalnum()
                       and seg[cut].isascii() and seg[cut].isalnum()):
                    cut += 1
            out.append(seg[start:cut].strip())
            start = cut
    return "<br/>".join([x for x in out if x])


def fix_label(m):
    return m.group(1) + '"' + wrap(m.group(2)) + '"' + m.group(3)


def fix_edge(m):
    return "|" + wrap(m.group(1), 13.0) + "|"


def main(path, dry=False):
    lines = io.open(path, encoding="utf-8").read().split("\n")
    # 先按块判定：横向布局且节点多/文本宽 -> 改纵向，避免整体超宽
    lr_to_td = set()
    i = 0
    while i < len(lines):
        if lines[i].startswith("```mermaid"):
            j = i + 1
            while j < len(lines) and lines[j].strip() != "```":
                j += 1
            head = lines[i + 1].strip()
            body = lines[i + 2:j]
            if head.endswith(" LR") or head.endswith("RL"):
                labels = re.findall(r'"([^"]*)"', "\n".join(body))
                ids = set(re.findall(r'^\s*([A-Za-z_][A-Za-z0-9_]*)', "\n".join(body), re.M))
                lr_to_td.add(i + 2)   # 一律纵向：横向长链在窄面板必然被截断
            i = j
        i += 1
    out, inm = [], False
    stat = {"blocks": 0, "labels": 0, "edges": 0, "td": 0}
    for idx, l in enumerate(lines, 1):
        if l.startswith("```mermaid"):
            inm = True
            stat["blocks"] += 1
            out += [l, INIT]
            continue
        if inm and l.strip() == "```":
            inm, _ = False, out.append(l)
            continue
        if inm:
            if idx in lr_to_td and l.strip().startswith("flowchart LR"):
                l = l.replace("flowchart LR", "flowchart TD")
                stat["td"] += 1
            new = re.sub(r'(\[|\{|\()"([^"]*)"(\]|\}|\))', fix_label, l)
            if new != l:
                stat["labels"] += 1
            new2 = re.sub(r'\|([^|\n"]+)\|', fix_edge, new)
            if new2 != new:
                stat["edges"] += 1
            out.append(new2)
            continue
        out.append(l)
    if not dry:
        io.open(path, "w", encoding="utf-8", newline="\n").write("\n".join(out))
    return stat


if __name__ == "__main__":
    print(main(sys.argv[1], dry=("--dry" in sys.argv)))
