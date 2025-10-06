# test_stix_debug.py

#!/usr/bin/env python3
"""
Test de debug pour vérifier les imports et créations STIX2
"""

try:
    from stix2 import Note, Indicator, Identity, TLP_WHITE
    from datetime import datetime, timezone # Utiliser timezone pour la compatibilité

    print("✅ Imports STIX2 réussis")

    # Test création Identity
    try:
        author = Identity(
            name="Test Author",
            identity_class="organization"
        )
        print("✅ Création Identity réussie")
    except Exception as e:
        print(f"❌ Erreur création Identity: {e}")

    # Test création Note
    try:
        note = Note(
            content="Test content",
            object_refs=["file--12345678-1234-5678-9abc-123456789abc"],
            object_marking_refs=[TLP_WHITE]
        )
        print("✅ Création Note réussie")
    except Exception as e:
        print(f"❌ Erreur création Note: {e}")

    # Test création Indicator
    try:
        indicator = Indicator(
            pattern="[file:hashes.MD5 = 'test']",
            pattern_type="stix", # <-- Ajoutez cette ligne
            labels=["malicious-activity"],
            valid_from=datetime.now(timezone.utc),
            object_marking_refs=[TLP_WHITE]
        )
        print("✅ Création Indicator réussie")
    except Exception as e:
        print(f"❌ Erreur création Indicator: {e}")

except ImportError as e:
    print(f"❌ Erreur d'import STIX2: {e}")