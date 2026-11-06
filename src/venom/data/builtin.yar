/*
 * Venom built-in rules.
 *
 * Real-world coverage comes from ClamAV and the rule feeds installed by `venom update`.
 * These rules exist so detection, archive inspection, and quarantine can be verified
 * end to end (`venom selftest`) on machines where other antivirus products would
 * immediately remove the EICAR test file.
 */

rule Venom_Test_File
{
    meta:
        description = "Venom antivirus test file (harmless)"
        severity = "low"
        category = "test"
    strings:
        // Hex-encoded so this rule file does not match itself.
        $marker = { 56 45 4E 4F 4D 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D 46 49 4C 45 }
    condition:
        $marker at 0
}
