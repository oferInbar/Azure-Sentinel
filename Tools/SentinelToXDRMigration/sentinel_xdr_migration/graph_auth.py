from __future__ import annotations

GRAPH_RESOURCE = "https://graph.microsoft.com"
GRAPH_RESOURCE_DEFAULT_SCOPE = f"{GRAPH_RESOURCE}/.default"


def credential_token_scope(auth_method: str, permission_scope: str) -> str:
    """Map an operation's permission scope to the selected credential contract.

    AzureCliCredential requests Azure CLI resource tokens. Its `/.default`
    scope maps to the Graph resource URI; other credentials keep the exact
    delegated permission scope.
    """
    if auth_method == "azure-cli":
        return GRAPH_RESOURCE_DEFAULT_SCOPE
    return permission_scope
