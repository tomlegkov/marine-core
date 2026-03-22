import sys

if sys.version_info[0] < 3:
    from imp import find_module
else:
    import importlib.util

    def find_module(module_name: str) -> tuple[None, str]:
        """
        A simplified version of imp.find_module for Python 3.4 and later.
        """

        spec = importlib.util.find_spec(module_name)

        if spec is None:
            # imp.find_module raises ImportError if the module is not found.
            # We replicate that behavior here.
            raise ImportError(f"No module named '{module_name}'")

        # imp.find_module returns (file, pathname, description).
        # pathname (index 1) is the path to the module file, or the module name for built-in modules.
        #
        # For file-based modules (e.g., .py files, shared libraries):
        #   spec.origin holds the path to the module file.
        # For built-in modules (e.g., 'sys', 'math'):
        #   spec.origin is None, but imp.find_module would return the module name itself as pathname.
        #   spec.name holds the module name.

        if spec.origin is not None:
            # This covers standard Python files and extension modules
            return (None, spec.origin)
        else:
            # This covers built-in modules where there isn't a physical file path
            # and imp.find_module would return the module name itself as the 'pathname'.
            return (None, spec.name)
