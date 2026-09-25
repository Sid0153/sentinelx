# ADR-0007: Backend-authoritative RBAC with a test-enforced route table

**Context.** There are three roles. The UI hides actions a role cannot take, but the UI must
not be the control.

**Decision.**
- Every route checks the role through a FastAPI dependency, and the role is read from the
  database on each request.
- `tests/api/test_rbac.py` holds the expected access for every route. It fails if a route is
  added without an entry, and it calls each route as anonymous, VIEWER, ANALYST and ADMIN.
- Denials are audited.

**Consequences.** Adding a route forces an explicit access decision. Object-level rules (for
example, saved hunts owned by one user) are tested separately.
