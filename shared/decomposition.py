SWITCHES = (
    "commitment",
    "fingerprint",
    "p1",
    "p2",
    "p3",
    "p4",
    "order1",
    "product1",
    "p5",
    "order2",
    "product2",
    "p6",
)

REQUIRES = {"p5": "order1", "p6": "order2"}

BINDING = ("commitment", "fingerprint")

GADGETS = ("p1", "p2", "p3", "p4")


class ConfigurationError(ValueError):
    pass


def validate(switches) -> tuple[str, ...]:
    enabled = set(switches)
    unknown = enabled - set(SWITCHES)
    if unknown:
        raise ConfigurationError(f"unknown switches {sorted(unknown)}; known are {list(SWITCHES)}")
    for switch, required in REQUIRES.items():
        if switch in enabled and required not in enabled:
            raise ConfigurationError(
                f"{switch} is an adjacency check on a claimed ordering, so it needs {required}; "
                "without it the check is the unsoundness the audit was built around"
            )
    return tuple(switch for switch in SWITCHES if switch in enabled)


def command_flag(switches) -> str:
    return "--enable=" + ",".join(validate(switches))


def parse(text: str) -> tuple[str, ...]:
    stripped = text.strip()
    if stripped in ("", "none"):
        return ()
    return validate(part.strip() for part in stripped.split(",") if part.strip())


_FLOOR: dict[str, tuple[str, ...]] = {
    "bare": (),
    "commitment_only": ("commitment",),
    "fingerprint_only": ("fingerprint",),
    "baseline": ("commitment", "fingerprint"),
}

_ISOLATED: dict[str, tuple[str, ...]] = {
    "p1_completeness": ("p1",),
    "p2_currentness": ("p2",),
    "p3_compliance": ("p3",),
    "p4_load_ratio": ("p4",),
    "order1_sortedness": ("order1",),
    "product1_permutation": ("product1",),
    "order2_sortedness": ("order2",),
    "product2_permutation": ("product2",),
    "sigma1_machinery": ("order1", "product1"),
    "sigma2_machinery": ("order2", "product2"),
    "p5_no_overlap": ("order1", "p5"),
    "p6_uniqueness": ("order2", "p6"),
    "both_sigma_machinery": ("order1", "product1", "order2", "product2"),
}

LEAVE_ONE_OUT = {switch: f"full_without_{switch}" for switch in SWITCHES}


CONFIGURATIONS: dict[str, tuple[str, ...]] = dict(_FLOOR)
for _name, _extra in _ISOLATED.items():
    CONFIGURATIONS[_name] = validate(set(_FLOOR["baseline"]) | set(_extra))
for _switch in SWITCHES:
    _remaining = set(SWITCHES) - {_switch}
    for _assertion, _ordering in REQUIRES.items():
        if _ordering not in _remaining:
            _remaining.discard(_assertion)
    CONFIGURATIONS[LEAVE_ONE_OUT[_switch]] = validate(_remaining)
CONFIGURATIONS["full"] = SWITCHES

TIMED = (
    "bare",
    "baseline",
    "p1_completeness",
    "p2_currentness",
    "p3_compliance",
    "p4_load_ratio",
    "sigma1_machinery",
    "sigma2_machinery",
    "both_sigma_machinery",
    "full",
)
