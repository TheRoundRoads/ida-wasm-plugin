"""Identifier hit testing independent of IDA's whitespace-based word API."""
import re

IDENTIFIER = re.compile(r'(?<![A-Za-z_0-9])[A-Za-z_][A-Za-z_0-9]*')


def identifier_at(line, column):
    """Return the identifier under a plain-text column, including its right edge.

    IDA's simple custom viewer GetCurrentWord() can return `_f1387(0);`,
    so it cannot be used directly as a symbol-table key.
    """
    if not isinstance(column,int) or column < 0:
        return None
    for match in IDENTIFIER.finditer(line):
        if match.start() <= column < match.end():
            return match[0]
        if column == match.end() and (column == len(line) or line[column] in '([;,. '):
            return match[0]
    return None


def symbol_at(line, column, symbols):
    name = identifier_at(line,column)
    return (name,symbols[name]) if name in symbols else (None,None)
