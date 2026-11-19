from cyber_quality_check.constants import SHORTCUT_PATH_RE


def test_does_not_match_os_environ_usage():
    text = "entry = next((c for c in cases if c.get('case_ref') == os.environ['CASE_REF']), None)"
    assert SHORTCUT_PATH_RE.search(text) is None


def test_does_not_match_environment_word():
    assert SHORTCUT_PATH_RE.search("os.environment_variable_name") is None


def test_matches_real_dotenv_reference():
    assert SHORTCUT_PATH_RE.search("cat .env | grep SECRET") is not None


def test_matches_seed_data_reference():
    assert SHORTCUT_PATH_RE.search("cat /app/seed_data/flag.txt") is not None


def test_matches_etc_passwd():
    assert SHORTCUT_PATH_RE.search("cat /etc/passwd") is not None
