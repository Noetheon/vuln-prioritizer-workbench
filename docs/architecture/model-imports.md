# Model Import Registry

The template backend keeps `app.models` as the public model import surface. API
routes, database setup, tests, and Alembic should import from `app.models`
instead of reaching into individual model modules.

Internally, model definitions are split by domain, such as auth DTOs, user
models, project models, and shared Workbench status DTOs. The aggregator
re-exports those classes through `app.models.__all__` so callers keep stable
imports while the files remain small enough to review.

Alembic depends on this convention. `app/alembic/env.py` imports
`import_table_models` from `app.models` and calls it before assigning
`target_metadata = SQLModel.metadata`. The registry in
`app.models.registry.TABLE_MODEL_MODULES` must include every module that declares
SQLModel table classes. A fresh database upgraded to Alembic head should
therefore match the metadata with no missing `user` or `project` table diffs.

When adding a new table model:

- create or update the focused module under `backend/app/models/`
- export the public class or DTO from `backend/app/models/__init__.py`
- add table-bearing modules to `TABLE_MODEL_MODULES`
- keep API and service imports pointed at `app.models`
- add a metadata/autogenerate test before relying on a new migration
