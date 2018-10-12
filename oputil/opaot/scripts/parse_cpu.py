from pathlib import Path

path = Path(r"C:\Users\EcmaXp\Dropbox\Projects\OpenPie\opmod\src\main\java\kr\pe\ecmaxp\thumbsk\CPU.kt")

prefix_blank = None

with path.open() as fp:
    has_if = []
    for line in fp:
        line = line.rstrip()

        if (("code" not in line and "->" not in line) or
                ("right" in line and "->" in line) or
                "else" in line or
                "code =" in line):
            continue

        if prefix_blank is None:
            prefix_blank = " " * (len(line) - len(line.lstrip(" ")))
            line = line[len(prefix_blank):]
            prefix_blank += " " * 4
        else:
            assert line.startswith(prefix_blank), line
            line = line[len(prefix_blank):]

        blank_count = len(line) - len(line.lstrip(" "))
        assert blank_count % 4 == 0
        level = blank_count // 4

        code = (line
                .replace("shr", ">>")
                .replace("and", "&")
                .replace("//", "#")
                .replace("{", ":")
                .replace("var ", "")
                .replace("val ", "")
                .replace("-> :", "->")
                )

        code, sep, comment = code.partition("#")
        code = code.rstrip()

        comments = [s.strip() for s in comment.split(";") if s and not s.strip().startswith(":")]

        if "->" in code:
            left, sep, right = code.partition("->")
            left = left.strip()
            assert left
            assert sep
            code = blank_count * " " + f"elif prefix == {left}: {right}"

        if code.startswith("when (") and code.endswith(") :"):
            code = "prefix = " + code[len("when ("):-len(") :")]

        print(code, "#" if comment else "", *comments)
