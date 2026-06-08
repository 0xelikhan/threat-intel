"""
FastAPI router modules — gradual extraction from main.py.

Pattern: each module exports a `router` (APIRouter) plus any request/
response models scoped to its routes. main.py mounts each via
`app.include_router(<module>.router)`.

Goal isn't to evacuate main.py — just to peel off the routes that are
self-contained and recently added (so existing tests + middleware paths
keep working unchanged). Calibration + sandbox are the first two; more
follow if/when the cost of leaving them in main.py outweighs the cost
of the move.
"""
