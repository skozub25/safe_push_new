from scanner.entropy import shannon_entropy

def test_entropy_empty_string():
    assert shannon_entropy("") == 0.0

def test_entropy_low_for_repeated_chars():
    assert shannon_entropy("AAAAAA") == 0.0

def test_entropy_higher_for_varied_chars_than_repeated():
    e_repeat = shannon_entropy("AAAAAA")
    e_mixed = shannon_entropy("ABCDEFabcdef")
    assert e_mixed > e_repeat

def test_entropy_secret_like_token_is_relatively_high():
    token = "Z7xY6wV5uT4sR3qP2oN1mL0kJ9"  # long, mixed, uniform-ish
    assert shannon_entropy(token) >= 4.0

def test_entropy_ignores_character_order():
    s1 = "AABBCCDD"
    s2 = "DDCCBBAA"
    assert shannon_entropy(s1) == shannon_entropy(s2)

def test_entropy_varied_string_greater_than_uniform_single_char():
    assert shannon_entropy("ABCDEF") > shannon_entropy("AAAAAA")
