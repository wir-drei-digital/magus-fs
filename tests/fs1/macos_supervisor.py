"""Reuse the qualified FS0 600s/5s guard; serving children are never group-killed."""
import importlib.util
from pathlib import Path
_spec=importlib.util.spec_from_file_location('fs1_qualified_supervisor',Path(__file__).resolve().parents[1]/'fs0/macos_supervisor.py')
_module=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_module)
supervise=_module.supervise
SupervisionFailure=_module.SupervisionFailure
