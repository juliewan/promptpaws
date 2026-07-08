from promptpaws.firewall.normalize import normalize


def test_plain_text_unchanged():
    assert normalize("please summarize this article") == "please summarize this article"


def test_strips_zero_width_characters():
    assert normalize("ig​no‌re") == "ignore"


def test_folds_fullwidth_via_nfkc():
    assert normalize("ｉｇｎｏｒｅ") == "ignore"


def test_maps_cyrillic_confusables():
    # "ignore" spelled with Cyrillic о and е
    assert normalize("ignоrе") == "ignore"


def test_strips_control_characters():
    assert normalize("hello\x00\x1fworld") == "helloworld"


def test_keeps_ordinary_whitespace():
    assert normalize("line one\nline two\ttabbed") == "line one\nline two\ttabbed"
