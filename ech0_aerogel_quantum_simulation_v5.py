#!/usr/bin/env python3
"""Deterministic estimator for the ECH0 V5 nano-composite aerogel recipe."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from aerogel_estimators import AerogelRecipe, evaluate_recipe, format_console_report


def main() -> dict:
    recipe = AerogelRecipe(
        name="ECH0 V5 nano-composite",
        freeze_temp_c=-20.0,
        base_material="sodium_silicate",
        pva_mass_fraction=1.0 / 3.0,
        mtms_wt_percent=8.5,
        glutaraldehyde_vol_percent=2.2,
        additives={
            "cnt": 1.2,
            "graphene": 0.5,
            "silica_np": 1.0,
            "tio2": 0.3,
            "mof": 0.4,
            "quantum_dots": 0.1,
        },
        drying_method="freeze_dry",
        target_transparency=90.0,
    )

    evaluation = evaluate_recipe(recipe)
    print(format_console_report(evaluation))

    report = {
        "timestamp": datetime.now().isoformat(),
        "model": "deterministic_v5_estimator",
        "recipe": {
            "name": recipe.name,
            "freeze_temp_c": recipe.freeze_temp_c,
            "base_material": recipe.base_material,
            "pva_mass_fraction": recipe.pva_mass_fraction,
            "mtms_wt_percent": recipe.mtms_wt_percent,
            "glutaraldehyde_vol_percent": recipe.glutaraldehyde_vol_percent,
            "additives": recipe.additives,
            "drying_method": recipe.drying_method,
            "target_transparency_percent": recipe.target_transparency,
        },
        "pore_statistics_nm": evaluation["pore_stats"],
        "transparency_percent": evaluation["transparency_percent"],
        "meets_transparency_target": evaluation["meets_transparency_target"],
        "structural_score": evaluation["structural_score"],
        "structural_breakdown": evaluation["structural_breakdown"],
        "verdict": evaluation["verdict"],
    }

    output_path = Path("~/repos/consciousness/ech0_aerogel_simulation_results_v5.json").expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport written to {output_path}")
    return report


if __name__ == "__main__":
    main()
