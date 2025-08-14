#!/usr/bin/env python3
"""
Demo script showing the new unified mint limits functionality.

This script demonstrates how to use the new mint_limits configuration
to set limits for multiple units in a single, unified way.
"""

from cashu.core.base import Unit
from cashu.core.settings import settings
from cashu.mint.verification import get_mint_limits


def demo_unified_limits():
    """Demonstrate the unified mint limits configuration."""
    print("=== Unified Mint Limits Demo ===\n")
    
    print("1. Setting up unified limits:")
    print("   mint_limits = [")
    print("       ['sat', 10000, 5000, 100000],")
    print("       ['usd', 100.0, 50.0, 1000.0],")
    print("       ['eur', None, 25.0, 500.0]")
    print("   ]")
    print()
    
    # Configure unified limits: [unit, max_mint, max_melt, max_balance]
    settings.mint_limits = [
        ["sat", 10000, 5000, 100000],
        ["usd", 100.0, 50.0, 1000.0],
        ["eur", None, 25.0, 500.0]  # None means no limit for max_mint
    ]
    
    # Get the parsed limits
    max_mint_map, max_melt_map, max_balance_map = get_mint_limits()
    
    print("2. Parsed limits:")
    for unit in [Unit.sat, Unit.usd, Unit.eur]:
        print(f"   {unit.name}:")
        print(f"     Max mint: {max_mint_map[unit]}")
        print(f"     Max melt: {max_melt_map[unit]}")
        print(f"     Max balance: {max_balance_map[unit]}")
        print()


def demo_mixed_configuration():
    """Demonstrate mixed configuration with some None values."""
    print("=== Mixed Configuration Demo ===\n")
    
    print("1. Setting up mixed limits (some None values):")
    print("   mint_limits = [")
    print("       ['sat', 15000, None, 150000],  # No melt limit")
    print("       ['usd', None, None, None]      # No limits at all")
    print("   ]")
    print()
    
    # Configure mixed limits
    settings.mint_limits = [
        ["sat", 15000, None, 150000],  # No melt limit
        ["usd", None, None, None]      # No limits at all
    ]
    
    # Get the parsed limits
    max_mint_map, max_melt_map, max_balance_map = get_mint_limits()
    
    print("2. Parsed limits:")
    for unit in [Unit.sat, Unit.usd]:
        print(f"   {unit.name}:")
        print(f"     Max mint: {max_mint_map[unit]}")
        print(f"     Max melt: {max_melt_map[unit]}")
        print(f"     Max balance: {max_balance_map[unit]}")
        print()


if __name__ == "__main__":
    demo_unified_limits()
    demo_mixed_configuration()
    
    print("=== Configuration Examples ===\n")
    print("Environment variable format:")
    print('MINT_LIMITS=\'[["sat", 10000, 5000, 100000], ["usd", 100.0, 50.0, 1000.0]]\'')
    print()
    print("Python format:")
    print('settings.mint_limits = [["sat", 10000, 5000, 100000], ["usd", 100.0, 50.0, 1000.0]]')
    print()
    print("Configuration file format (.env):")
    print('MINT_LIMITS=[["sat", 10000, 5000, 100000], ["usd", 100.0, 50.0, 1000.0]]')
