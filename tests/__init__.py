"""
Test suite package initializer.

The previous file was encrypted via git-crypt, which prevented pytest from
importing the test package (resulting in ``SyntaxError: source code string
cannot contain null bytes``).  This lightweight module simply declares the
package so discovery works consistently across environments.
"""

__all__: list[str] = []
