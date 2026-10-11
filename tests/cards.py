MODERN_CARD = {
    "name": "Travel Agent",
    "description": "Books flights and hotels",
    "version": "1.2.0",
    "supportedInterfaces": [
        {"url": "https://agents.example/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
    ],
    "capabilities": {"streaming": True, "pushNotifications": False, "extendedAgentCard": False},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "book", "name": "Book flight", "description": "Books a flight", "tags": ["travel"]}],
    "securitySchemes": {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer"}}},
    "security": [{"bearer": []}],
}

LEGACY_CARD = {
    "name": "Old Agent",
    "url": "http://10.1.2.3:8000/",
    "version": "0.2.1",
    "capabilities": {"streaming": True, "pushNotifications": True},
    "skills": [{"id": "s", "name": "S", "description": "does s"}],
    "authentication": {"schemes": []},
}
