def standardized_response(success=True, data=None, status=True, message=None, error=None, **kwargs):

    """
    Generate a standardized response format for API responses.
    Args:
        success (bool): Indicates if the operation was successful.
        data (dict): The payload of the response.
        error (str): Error message if unsuccessful. Defaults to None.
        message (str): Informational message. Defaults to None.
        status (bool): Status of the response.
        kwargs: Additional key-value pairs to include in the response.
    Returns:
        dict: Standardized response dictionary.
    """

    response = {
        "success": success,
        "data": data if data is not None else {},
        "error": error if error is not None else "",
        "status": status,
        "message": message,
    }

    response.update(kwargs)
    return response