#!/usr/bin/env python3
"""Generate the METHOD-level baseline profile rules (static analysis).

The ART baseline profile format cannot express "compile package X" as a
method rule — wildcards only expand at CLASS level (and class rules alone
pre-verify but never AOT-compile methods). The complete method surface of
the pinned library versions is statically derivable from the jars, so this
script enumerates it with javap and emits explicit
    HSPL<class>;-><name><descriptor>
rules for every concrete method in the scoped packages.

Usage:  python3 scripts/gen-baseline-profile.py
Run after a DEPENDENCY BUMP (the jar versions below are pinned to
android/app/build.gradle.kts). The rules land in
android/app/src/main/baseline-prof.txt between the GENERATED markers;
AGP maps them through the R8 mapping at assembleRelease (verified: the
class rules from the same file land on the obfuscated dex).

The generated set is a SUPERSET of "hot" (it includes error paths a
benchmark would never hit): a larger one-time bg-dexopt compile after
install, in exchange for zero device/CI infrastructure.
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "android/app/src/main/baseline-prof.txt"

# (jar, package prefixes) — versions pinned to build.gradle.kts.
JARS = [
    (Path.home() / ".gradle/caches/modules-2/files-2.1/org.eclipse.jgit/"
     "org.eclipse.jgit/7.7.1.202607240634-r/"
     "56ae76f632f5565dd838fc13c73db89c449a17ed/"
     "org.eclipse.jgit-7.7.1.202607240634-r.jar",
     ["org/eclipse/jgit/"]),
    (Path.home() / ".gradle/caches/modules-2/files-2.1/com.github.mwiede/"
     "jsch/0.2.17/1572f8ac4023895c2232160fddd4bfdd8c8e214d/jsch-0.2.17.jar",
     ["com/jcraft/jsch/"]),
    (Path.home() / ".gradle/caches/modules-2/files-2.1/org.bouncycastle/"
     "bcprov-jdk18on/1.79/4d8e2732bcee15f1db93df266c3f5b70ce5cac21/"
     "bcprov-jdk18on-1.79.jar",
     ["org/bouncycastle/crypto/", "org/bouncycastle/openpgp/"]),
    (Path.home() / ".gradle/caches/modules-2/files-2.1/org.bouncycastle/"
     "bcpg-jdk18on/1.79/904dd8a8e1c9f7d58d1ffa7f4ca3fb00736a601f/"
     "bcpg-jdk18on-1.79.jar",
     ["org/bouncycastle/openpgp/"]),
]

BEGIN = "# BEGIN GENERATED (scripts/gen-baseline-profile.py — do not edit)"
END = "# END GENERATED"

# javap -p -s prints, per member: a declaration line, then a
# "descriptor: (params)ret" line. The method name = the LAST identifier
# immediately before "(" on the declaration line; a constructor is the
# case where that identifier equals the class's simple name (javap
# prints constructors without a return type). Fields have no "(" and
# their descriptor lines are skipped because no declaration is pending.
# abstract/native members have no bytecode to AOT-compile — skipped.
NAME_RE = re.compile(r"([\w$]+)\(")
# javap prints the descriptor VERBATIM as the full JNI descriptor —
# the trailing ";" on L-types is part of the descriptor itself, not
# punctuation (stripping it breaks the dex lookup for every
# L-type-returning method). Capture the whole thing.
DESC_RE = re.compile(r"^ *descriptor: (\(\S*\)\S+)$")
CLASS_RE = re.compile(
    r"^ *(?:public |protected |private )*(?:abstract |final |static |"
    r"sealed |non-sealed )*(?:class|interface|enum) ([\w.<>]+)")
SKIP_RE = re.compile(r"\b(abstract|native)\b")


def class_list(jar: Path, prefixes: list[str]) -> list[str]:
    listing = subprocess.run(["jar", "tf", str(jar)], capture_output=True,
                             text=True, check=True).stdout
    names = set()
    for line in listing.splitlines():
        if not line.endswith(".class"):
            continue
        name = line[:-len(".class")]  # inner classes keep their $ form
        if "module-info" in name or "package-info" in name:
            continue
        if any(name.startswith(p) for p in prefixes):
            names.add(name)
    return sorted(names)


def methods(jar: Path, cp: str, classes: list[str]) -> set[str]:
    rules = set()
    for i in range(0, len(classes), 200):
        batch = [c.replace("/", ".") for c in classes[i:i + 200]]
        out = subprocess.run(
            ["javap", "-p", "-s", "-cp", cp] + batch,
            capture_output=True, text=True, check=True).stdout
        current = None      # the current class's FQ name (dots)
        pending = None      # the last declaration line seen
        for line in out.splitlines():
            head = CLASS_RE.match(line)
            if head:
                # javap prints inner classes as Outer.Inner
                current = head.group(1).split("<")[0]
                pending = None
                continue
            if current is None:
                continue
            if "(" in line and not line.strip().startswith("descriptor:"):
                pending = line
                continue
            m = DESC_RE.match(line)
            if m and pending is not None and not SKIP_RE.search(pending):
                names = NAME_RE.findall(pending)
                if names:
                    name = names[-1]
                    if name == current.rsplit(".", 1)[-1]:
                        name = "<init>"
                    # HRF: HSPL<slashed-class>;-><name><descriptor>
                    rules.add(
                        f"HSPL{current.replace('.', '/')};->{name}{m.group(1)}")
            if m:
                pending = None
    return rules


def main() -> None:
    missing = [str(j) for j, _ in JARS if not j.exists()]
    if missing:
        sys.exit("jars not found (bump the pinned versions):\n" +
                 "\n".join(missing))

    cp = ":".join(str(j) for j, _ in JARS)
    rules = set()
    for jar, prefixes in JARS:
        classes = class_list(jar, prefixes)
        print(f"{jar.name}: {len(classes)} classes")
        rules |= methods(jar, cp, classes)

    text = OUT.read_text()
    if BEGIN not in text or END not in text:
        text = text.rstrip() + f"\n\n{BEGIN}\n{END}\n"
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    body = "\n".join(sorted(rules))
    OUT.write_text(head + BEGIN + "\n" + body + "\n" + END + tail)
    print(f"wrote {len(rules)} method rules to {OUT}")


if __name__ == "__main__":
    main()
