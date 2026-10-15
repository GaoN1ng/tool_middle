"""Decode source consistently for both independent and upstream engines."""


def decode_source(raw):
    try:
        return raw.decode('utf-8'), 'utf-8'
    except UnicodeDecodeError:
        # Some upstream C comments use Windows punctuation. This is strict:
        # invalid CP1252 bytes still raise, and no replacement characters hide errors.
        return raw.decode('cp1252'), 'cp1252_fallback'
