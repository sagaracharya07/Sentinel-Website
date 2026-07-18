"""Gmail integration layer for Sentinel.

Kept out of the Flask route handlers on purpose: OAuth, token refresh,
label management, message retrieval and MIME parsing are all here as
importable, unit-testable units. Routes stay thin and delegate here.
"""
