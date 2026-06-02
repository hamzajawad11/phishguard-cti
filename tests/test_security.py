from app.security import is_safe_host, is_safe_url


def test_blocks_private_and_internal_addresses():
    assert is_safe_url("http://127.0.0.1/") is False
    assert is_safe_url("http://10.0.0.1/admin") is False
    assert is_safe_url("http://192.168.1.1/") is False
    assert is_safe_url("http://169.254.169.254/latest/meta-data/") is False
    assert is_safe_url("http://[::1]/") is False


def test_blocks_non_http_schemes():
    assert is_safe_url("ftp://example.com/") is False
    assert is_safe_url("file:///etc/passwd") is False


def test_allows_public_ip_literals():
    assert is_safe_url("http://8.8.8.8/") is True
    assert is_safe_url("https://1.1.1.1/") is True


def test_is_safe_host_with_literals():
    assert is_safe_host("127.0.0.1") is False
    assert is_safe_host("8.8.8.8") is True
    assert is_safe_host("") is False
