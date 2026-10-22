# Python API

All grading entry points are `async` and return a [`Report`](#report). The base import is light.
Heavy dependencies load only when the feature that needs them runs.

```python
import asyncio
from audel import check, listen

report = asyncio.run(check("promo.wav", spec="ebu_r128_s1"))
```

## Grading

::: audel.core.check.check

::: audel.core.listen.listen

::: audel.core.analyze.analyze

::: audel.core.watch.watch

::: audel.core.render.render

## Delivery specs

::: audel.specs.DeliverySpec

::: audel.specs.builtin_spec

::: audel.specs.resolve_spec

## Report

::: audel.models.Report
    options:
      members: false

::: audel.models.TrackSummary
    options:
      members: false

::: audel.models.ListeningSummary
    options:
      members: false

## Configuration

::: audel.config.load_settings
