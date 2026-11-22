from rift.targets import collect_targets, parse_url_lines


def test_parser_skips_comments_and_duplicates():
    text = """
    # comment
    https://app.example.com/login

    https://app.example.com/login
    https://app.example.com/floor
    """
    assert parse_url_lines(text) == [
        "https://app.example.com/login",
        "https://app.example.com/floor",
    ]


def test_collect_targets_reads_a_text_file(tmp_path):
    path = tmp_path / "urls.txt"
    path.write_text("# skip\nhttps://app.example.com/login\n", encoding="utf-8")
    assert collect_targets([str(path), "https://app.example.com/floor"]) == [
        "https://app.example.com/login",
        "https://app.example.com/floor",
    ]
