"""ForgeLab domain modules.

Each domain owns its tables, commands, events, and policy checks. The deployment
unit stays a single modular monolith; domains communicate through explicit
domain events rather than reaching into each other's internals.
"""
