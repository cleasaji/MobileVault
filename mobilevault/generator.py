import math
import secrets
import string

AMBIGUOUS = set("Il1O0o")
WORDS = ("anchor basil cobalt dune ember falcon glacier harbor iris jungle kelp lantern meadow nectar orbit pebble "
         "quartz raven saffron tundra umber velvet willow xenon yarrow zephyr bramble cinder dapple eclipse "
         "fjord gadget hollow ivory juniper kestrel lagoon mosaic nimbus opal prairie quiver ripple summit "
         "thistle upland vortex wander yonder zenith acorn breeze copper dahlia").split()


def generate_password(length: int = 20, symbols: bool = True, avoid_ambiguous: bool = False) -> str:
    if length < 8:
        raise ValueError("length must be at least 8")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits] + ([string.punctuation] if symbols else [])
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    chars = [secrets.choice(p) for p in pools]               # guarantee every class appears
    allc = "".join(pools)
    chars += [secrets.choice(allc) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words: int = 5, sep: str = "-") -> str:
    return sep.join(secrets.choice(WORDS) for _ in range(words))


def entropy_bits(pw: str) -> float:
    """Upper-bound estimate from character classes used (not a guarantee for human-chosen passwords)."""
    pool = 26 * any(c.islower() for c in pw) + 26 * any(c.isupper() for c in pw) + \
        10 * any(c.isdigit() for c in pw) + 32 * any(c in string.punctuation for c in pw)
    return round(len(pw) * math.log2(pool), 1) if pool else 0.0
