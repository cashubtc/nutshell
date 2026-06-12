"""Compatibility exports for core domain models.

The concrete implementations live in :mod:`cashu.core.domain`. New code should
import from the focused domain modules directly; this module keeps the existing
``cashu.core.base`` API stable for downstream users and older internal imports.
"""

from .domain import *  # noqa: F403
