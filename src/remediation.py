def remediate_storage_config(config):
    """
    Simulate remediation of a public cloud storage configuration.
    This function changes only the supplied Python dictionary.
    It does not connect to or modify any cloud resources.
    """
    updated_config = config.copy()

    if updated_config.get("public_access") is True:
        updated_config["public_access"] = False
        updated_config["status"] = "REMEDIATED"
        updated_config["message"] = (
            "Public access disabled in the simulation."
        )
    else:
        updated_config["status"] = "SECURE"
        updated_config["message"] = (
            "No public-access remediation required."
        )

    return updated_config


if __name__ == "__main__":
    example_config = {
        "resource": "example-storage",
        "public_access": True,
    }

    print("Before remediation:")
    print(example_config)

    result = remediate_storage_config(example_config)

    print("\nAfter simulated remediation:")
    print(result)
