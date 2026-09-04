import io

p = r"c:\Users\Admin\Documents\GitHub\ss-zapret2\panel\conn_tracker.py"
with io.open(p, encoding="utf-8") as f:
    s = f.read()

# защитим легальные фигурные скобки (dict-литералы(
s = s.replace("{}", "\u0000EMPTY\u0000")
s = s.replace('{"first":ts,"last":ts,"state":st}', "\u0000CONN\u0000")
s = s.replace('{"first": now,"last": now,"state": st}', "\u0000CONN2\u0000")
s = s.replace('{c: dict(v) for c, v in self._conns.items()}', "\u0000PREV\u0000")

# кривые «}» вместо «)» — только в коде, литералы защищены
s = s.replace("}", ")")

# нормализация полноширинных знаков и мусора
s = s.replace("\uff1a", ":")
s = s.replace("\uff1b", ";")
s = s.replace("\uff0c", ",")
s = s.replace("\u3002", ".")
s = s.replace("\uff08", "(")
s = s.replace("\uff09", ")")
s = s.replace("\u3010", "[")
s = s.replace("\u3011", "]")
s = s.replace("\u300c", '"')
s = s.replace("\u300d", '"')
s = s.replace("\u300e", '"')
s = s.replace("\u300f", '"')
s = s.replace("\uff01", "!")
s = s.replace("\uff1f", "?")
s = s.replace("\uff1d", "=")
s = s.replace("\u3000", " ")
s = s.replace("\u200b", "")
s = s.replace("\uff0e", ".")

# восстановим литералы
s = s.replace("\u0000EMPTY\u0000", "{}")
s = s.replace("\u0000CONN\u0000", '{"first":ts,"last":ts,"state":st}')
s = s.replace("\u0000CONN2\u0000", '{"first": now,"last": now,"state": st}')
s = s.replace("\u0000PREV\u0000", '{c: dict(v) for c, v in self._conns.items()}')

with io.open(p, "w", encoding="utf-8", newline="") as f:
    f.write(s)

print("normalized")