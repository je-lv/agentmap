from agentmap.analysis.toolrisk import HIGH_RISK, classify_tool


def test_name_based_classification():
    assert classify_tool("run_command", "")["exec"] == "name"
    assert classify_tool("executeShell", "")["exec"] == "name"
    assert classify_tool("write_file", "")["filesystem_write"] == "name"
    assert classify_tool("fetch_url", "")["http_fetch"] == "name"
    assert classify_tool("run_query", "")["sql"] == "name"
    assert classify_tool("get_secret", "")["secrets"] == "name"
    assert classify_tool("kubectl_apply", "")["cloud_admin"] == "name"


def test_schema_parameters_classify():
    schema = {"type": "object", "properties": {"command": {"type": "string"}}}
    assert classify_tool("do_thing", "", schema) == {"exec": "schema"}
    schema = {"properties": {"sql": {"type": "string"}}}
    assert classify_tool("do_thing", "", schema) == {"sql": "schema"}


def test_description_is_weakest_signal():
    got = classify_tool("helper", "Runs a shell command on the host")
    assert got == {"exec": "description"}


def test_benign_tool_has_no_classes():
    assert classify_tool("get_weather", "Returns the forecast for a city") == {}


def test_high_risk_set_is_exact():
    assert HIGH_RISK == {"exec", "filesystem_write", "http_fetch", "sql", "secrets", "cloud_admin"}


def test_non_string_inputs_do_not_raise():
    assert classify_tool("x", None, {"properties": "oops"}) == {}
